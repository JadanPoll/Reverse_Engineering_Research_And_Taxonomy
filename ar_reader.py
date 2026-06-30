"""
ar_reader.py — Extract function symbols from static library (.a) archives.

Static libraries are ar archives of .o (ELF relocatable) files.
Unlike stripped shared libraries (.so), .o files retain full .symtab
with ALL internal symbols — including codec internals like x264's
motion estimation, DCT, entropy coder, etc.

Addresses in .o files are section-relative (not absolute VAs), so we
set base_va=0 and use the symbol's section offset as the VA.
pypcode lifts them correctly since it only needs bytes + a base address.
"""
from __future__ import annotations
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

MAX_FN_SIZE = 8000
MIN_FN_SIZE = 4


def _parse_ar(data: bytes):
    """Yield (member_name, member_bytes) from an ar archive."""
    if data[:8] != b'!<arch>\n':
        return
    pos = 8
    while pos < len(data):
        if pos + 60 > len(data):
            break
        hdr  = data[pos:pos+60]
        name = hdr[0:16].decode('ascii', errors='replace').strip().rstrip('/')
        size = int(hdr[48:58].strip())
        pos += 60
        yield name, data[pos:pos+size]
        pos += size
        if size % 2:
            pos += 1   # ar pads to even bytes


def _extract_obj_functions(obj_data: bytes, obj_name: str) -> list[dict]:
    """Extract function symbols + bytes from a single .o ELF relocatable."""
    import io
    results = []
    try:
        elf = ELFFile(io.BytesIO(obj_data))

        # Only handle x86-64 relocatable objects
        if elf['e_machine'] not in ('EM_X86_64', 'EM_386', 'EM_RISCV', 'EM_ARM'):
            return []
        if elf['e_type'] != 'ET_REL':
            return []

        # Get symbol table (.symtab preferred, .dynsym fallback)
        symtab = elf.get_section_by_name('.symtab')
        if symtab is None or not isinstance(symtab, SymbolTableSection):
            return []

        # Build section → (offset_in_file, data) map
        sec_data = {}
        for sec in elf.iter_sections():
            if sec['sh_type'] in ('SHT_PROGBITS', 'SHT_NOBITS') and sec['sh_size'] > 0:
                try:
                    sec_data[sec.name] = (sec['sh_offset'], sec.data())
                except Exception:
                    pass

        # Collect STT_FUNC symbols with defined sections
        syms = []
        for sym in symtab.iter_symbols():
            if sym['st_info']['type'] != 'STT_FUNC':
                continue
            if sym['st_shndx'] in ('SHN_UNDEF', 'SHN_ABS', 'SHN_COMMON'):
                continue
            size = sym['st_size']
            if size < MIN_FN_SIZE or size > MAX_FN_SIZE:
                continue
            name = sym.name or f'fn_{sym["st_value"]:x}'
            # Resolve section name
            try:
                sec_idx = sym['st_shndx']
                sec = elf.get_section(sec_idx)
                sec_name = sec.name
                offset_in_sec = sym['st_value']
                if sec_name in sec_data:
                    _, sdata = sec_data[sec_name]
                    fn_bytes = sdata[offset_in_sec:offset_in_sec + size]
                    if len(fn_bytes) >= MIN_FN_SIZE:
                        syms.append({
                            'name': f'{obj_name}::{name}',
                            'va':   offset_in_sec,
                            'size': size,
                            'bytes': fn_bytes,
                        })
            except Exception:
                continue

        results.extend(syms)
    except Exception:
        pass
    return results


def extract_functions_from_archive(a_path: str) -> list[dict]:
    """
    Extract all function symbols from a static library (.a).
    Returns list of {'name', 'va', 'size', 'bytes'} — same format as elf_reader.
    """
    with open(a_path, 'rb') as f:
        data = f.read()

    all_fns = []
    for obj_name, obj_data in _parse_ar(data):
        if not obj_name or not obj_data:
            continue
        # Only process ELF objects (skip symbol index entries like '/', '//')
        if len(obj_data) < 4 or obj_data[:4] != b'\x7fELF':
            continue
        fns = _extract_obj_functions(obj_data, obj_name)
        all_fns.extend(fns)

    return all_fns
