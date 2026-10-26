"""
pe_utils.py — PE/PE32+ header parser: VA <-> file-offset, section lookup.
No third-party deps (stdlib struct only).  Works for 32-bit and 64-bit PE.

H=1 module: owns all PE-math facts. Every other tool imports from here.
Running this file directly confirms the parser against a known binary.

CLI usage:
    py pe_utils.py <dll/exe>                       # print section table
    py pe_utils.py <dll/exe> 0x1eb1df8             # file offset -> VA
    py pe_utils.py <dll/exe> 0x181eb1df8           # VA -> section + file offset
    py pe_utils.py --verify                        # run _verify() against ground_truth target
"""
import struct, sys, os


class PE:
    """Parse a PE/PE32+ file's headers for VA <-> file-offset conversions."""

    def __init__(self, path: str):
        self.path = path
        with open(path, 'rb') as f:
            dos = f.read(0x40)
            if dos[:2] != b'MZ':
                raise ValueError(f"Not a PE file: {path}")
            e_lfanew = struct.unpack_from('<I', dos, 0x3c)[0]
            f.seek(0)
            raw = f.read(e_lfanew + 0x2000)
        self._parse(e_lfanew, raw)

    def _parse(self, e_lfanew: int, raw: bytes):
        pe = e_lfanew
        if raw[pe:pe + 4] != b'PE\x00\x00':
            raise ValueError(f"PE signature not found at offset 0x{pe:x}")

        num_sections = struct.unpack_from('<H', raw, pe + 6)[0]
        size_opt     = struct.unpack_from('<H', raw, pe + 20)[0]

        opt   = pe + 24
        magic = struct.unpack_from('<H', raw, opt)[0]
        if magic == 0x20b:      # PE32+ (64-bit)
            self.image_base = struct.unpack_from('<Q', raw, opt + 24)[0]
            self.bits = 64
        elif magic == 0x10b:    # PE32 (32-bit)
            self.image_base = struct.unpack_from('<I', raw, opt + 28)[0]
            self.bits = 32
        else:
            raise ValueError(f"Unknown OptionalHeader magic 0x{magic:x}")

        sect_base = opt + size_opt
        self.sections: list[dict] = []
        for i in range(num_sections):
            s = sect_base + i * 40
            if s + 40 > len(raw):
                raise ValueError(
                    f"Section table truncated at entry {i} — "
                    f"increase read window in PE.__init__")
            name     = raw[s:s + 8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize    = struct.unpack_from('<I', raw, s + 8)[0]
            vrva     = struct.unpack_from('<I', raw, s + 12)[0]
            raw_size = struct.unpack_from('<I', raw, s + 16)[0]
            raw_off  = struct.unpack_from('<I', raw, s + 20)[0]
            chars    = struct.unpack_from('<I', raw, s + 36)[0]
            self.sections.append(dict(name=name, vrva=vrva, vsize=vsize,
                                      raw_off=raw_off, raw_size=raw_size,
                                      chars=chars))

    # ── conversions ───────────────────────────────────────────────────────────

    def va_to_rva(self, va: int) -> int:
        return va - self.image_base

    def rva_to_va(self, rva: int) -> int:
        return rva + self.image_base

    def va_to_file_offset(self, va: int) -> int:
        rva = va - self.image_base
        for s in self.sections:
            span = max(s['vsize'], s['raw_size'])
            if s['vrva'] <= rva < s['vrva'] + span:
                return s['raw_off'] + (rva - s['vrva'])
        raise ValueError(
            f"VA 0x{va:016x} (RVA 0x{rva:08x}) not in any section "
            f"(image_base=0x{self.image_base:016x})")

    def file_offset_to_va(self, file_off: int) -> int:
        for s in self.sections:
            if s['raw_size'] and s['raw_off'] <= file_off < s['raw_off'] + s['raw_size']:
                return self.image_base + s['vrva'] + (file_off - s['raw_off'])
        raise ValueError(f"File offset 0x{file_off:x} not in any section")

    def section_for_va(self, va: int) -> str | None:
        rva = va - self.image_base
        for s in self.sections:
            span = max(s['vsize'], s['raw_size'])
            if s['vrva'] <= rva < s['vrva'] + span:
                return s['name']
        return None

    def is_valid_va(self, va: int) -> bool:
        return self.section_for_va(va) is not None

    def describe_va(self, va: int) -> str:
        sect = self.section_for_va(va)
        rva  = va - self.image_base
        try:
            off = self.va_to_file_offset(va)
            return (f"VA=0x{va:016x}  RVA=0x{rva:08x}  "
                    f"FileOff=0x{off:08x}  [{sect or '?'}]")
        except ValueError:
            return f"VA=0x{va:016x}  RVA=0x{rva:08x}  [not in any section]"

    def describe_file_offset(self, file_off: int) -> str:
        try:
            va = self.file_offset_to_va(file_off)
            return f"FileOff=0x{file_off:08x}  ->  {self.describe_va(va)}"
        except ValueError as e:
            return f"FileOff=0x{file_off:08x}  [ERROR: {e}]"

    def summary(self) -> str:
        lines = [f"ImageBase : 0x{self.image_base:016x}  ({self.bits}-bit PE)",
                 f"Sections  : {len(self.sections)}"]
        for s in self.sections:
            va_s = self.image_base + s['vrva']
            va_e = va_s + max(s['vsize'], s['raw_size'])
            lines.append(
                f"  {s['name']:<10s}  VA 0x{va_s:016x}-0x{va_e:016x}"
                f"  FileOff 0x{s['raw_off']:08x}  RawSize 0x{s['raw_size']:08x}"
            )
        return '\n'.join(lines)


# ── Self-test ──────────────────────────────────────────────────────────────────

def _verify():
    """
    Confirm the parser against ground_truth.TARGET_DLL.
    Anchored to real measurements from Hss.Store.Client.dll (2025 build).

    POSITIVE: known section names, imagebase, VA->offset for confirmed functions.
    NEGATIVE: out-of-range VA must raise, not silently succeed.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from ground_truth import TARGET_DLL, IMAGE_BASE, KNOWN_VAS

    pe = PE(TARGET_DLL)

    # POSITIVE: imagebase must match ground_truth
    assert pe.image_base == IMAGE_BASE, \
        f"ImageBase mismatch: {pe.image_base:#x} != {IMAGE_BASE:#x}"
    assert pe.bits == 64, f"Expected 64-bit PE, got {pe.bits}-bit"

    # POSITIVE: anchored section count + known section names from real run
    assert len(pe.sections) == 6, \
        f"Expected 6 sections, got {len(pe.sections)}: {[s['name'] for s in pe.sections]}"
    names = {s['name'] for s in pe.sections}
    for expected in ('.rdata', '.data', '.pdata', '.text'):
        assert expected in names, f"Expected section {expected!r} not found"

    # POSITIVE: every KNOWN_VA must land in a section and produce a valid file offset
    for label, va in KNOWN_VAS.items():
        off = pe.va_to_file_offset(va)
        assert off > 0, f"KNOWN_VAS[{label!r}] = 0x{va:x} -> offset 0"
        # Round-trip: file_offset -> va must give back the same VA (within section)
        rt_va = pe.file_offset_to_va(off)
        assert rt_va == va, \
            f"Round-trip failed for {label!r}: 0x{va:x} -> off 0x{off:x} -> VA 0x{rt_va:x}"

    # NEGATIVE: VA before imagebase must raise
    try:
        pe.va_to_file_offset(0x1000)
        assert False, "Expected ValueError for VA below imagebase"
    except ValueError:
        pass

    # NEGATIVE: VA far beyond binary must raise
    try:
        pe.va_to_file_offset(IMAGE_BASE + 0x40000000)
        assert False, "Expected ValueError for VA beyond binary"
    except ValueError:
        pass

    print("OK: pe_utils.py verified")
    print(f"  {pe.bits}-bit PE  imagebase={pe.image_base:#x}  {len(pe.sections)} sections")
    print(f"  {len(KNOWN_VAS)} KNOWN_VAS all map to valid file offsets")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '--verify':
        _verify()
        sys.exit(0)

    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    pe = PE(sys.argv[1])
    print(pe.summary())

    for arg in sys.argv[2:]:
        val = int(arg, 16) if arg.startswith('0x') or arg.startswith('0X') else int(arg, 0)
        if val >= pe.image_base:
            print(f"  {pe.describe_va(val)}")
        else:
            print(f"  {pe.describe_file_offset(val)}")
