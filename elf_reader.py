"""
elf_reader.py — Extract function symbols and bytes from Linux ELF shared libraries.

Approach (from binary analysis literature):
  1. Read .symtab (full) → .dynsym (exports only) as fallback
  2. Filter to STT_FUNC, non-SHN_UNDEF, non-zero VA
  3. For st_size == 0: use next symbol's VA as end (heuristic, standard practice)
  4. Map VA → file offset using PT_LOAD segments
  5. Skip PLT stubs (typically <20 bytes, at .plt section address)

References:
  - pyelftools: https://www.programcreek.com/python/example/105189/elftools.elf.elffile.ELFFile
  - Zero-size heuristic: https://e2e.ti.com/support/tools/code-composer-studio-group/ccs/f/342385
  - Symbol filtering: https://eklitzke.org/parse-elf
"""
from __future__ import annotations
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.segments import Segment

MAX_FN_SIZE = 8000
MIN_FN_SIZE = 4


def _load_segments(elf: ELFFile) -> list[tuple[int, int, int]]:
    """Return list of (vaddr, file_offset, filesz) for PT_LOAD segments."""
    segs = []
    for seg in elf.iter_segments():
        if seg['p_type'] == 'PT_LOAD' and seg['p_filesz'] > 0:
            segs.append((seg['p_vaddr'], seg['p_offset'], seg['p_filesz']))
    return segs


def _va_to_file_offset(va: int, segments: list) -> int | None:
    for vaddr, foff, fsz in segments:
        if vaddr <= va < vaddr + fsz:
            return foff + (va - vaddr)
    return None


def _plt_range(elf: ELFFile) -> tuple[int, int] | None:
    """Return (start_va, end_va) of .plt section to skip stubs."""
    sec = elf.get_section_by_name('.plt')
    if sec:
        return sec['sh_addr'], sec['sh_addr'] + sec['sh_size']
    return None


def extract_functions(so_path: str) -> list[dict]:
    """
    Extract function symbols from an ELF shared library.
    Returns list of {'name': str, 'va': int, 'size': int}.
    """
    with open(so_path, 'rb') as f:
        elf = ELFFile(f)

        if elf['e_machine'] not in ('EM_X86_64', 'EM_386'):
            raise ValueError(f'Unsupported architecture: {elf["e_machine"]}')

        segments = _load_segments(elf)
        plt      = _plt_range(elf)

        # Prefer .symtab (full), fall back to .dynsym (exports only)
        symtab = elf.get_section_by_name('.symtab')
        if symtab is None or not isinstance(symtab, SymbolTableSection):
            symtab = elf.get_section_by_name('.dynsym')
        if symtab is None:
            return []

        # Collect all STT_FUNC symbols with defined addresses
        raw = []
        for sym in symtab.iter_symbols():
            if sym['st_info']['type'] != 'STT_FUNC':
                continue
            if sym['st_shndx'] == 'SHN_UNDEF':
                continue
            va   = sym['st_value']
            size = sym['st_size']
            name = sym.name or f'fn_{va:x}'
            if va == 0:
                continue
            # Skip PLT stubs
            if plt and plt[0] <= va < plt[1]:
                continue
            raw.append({'name': name, 'va': va, 'size': size})

        if not raw:
            return []

        # Sort by VA for next-symbol size heuristic
        raw.sort(key=lambda x: x['va'])

        # Fill in size == 0 using next symbol's VA
        for i, sym in enumerate(raw):
            if sym['size'] == 0:
                if i + 1 < len(raw):
                    sym['size'] = raw[i+1]['va'] - sym['va']
                else:
                    sym['size'] = 64   # last function: guess 64 bytes

        # Filter by size bounds and verify bytes are reachable
        results = []
        raw_bytes = f.read()  # already at end — re-read? no, need to seek

    # Re-read for byte extraction (file closed above)
    with open(so_path, 'rb') as f:
        raw_data = f.read()

    with open(so_path, 'rb') as f:
        elf      = ELFFile(f)
        segments = _load_segments(elf)

    for sym in raw:
        sz = sym['size']
        if sz < MIN_FN_SIZE or sz > MAX_FN_SIZE:
            continue
        foff = _va_to_file_offset(sym['va'], segments)
        if foff is None or foff + sz > len(raw_data):
            continue
        results.append({
            'name': sym['name'],
            'va':   sym['va'],
            'size': sz,
            'bytes': raw_data[foff:foff + sz],
        })

    return results


def elf_image_base(so_path: str) -> int:
    """Return the preferred load VA (base address) of the ELF."""
    with open(so_path, 'rb') as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] > 0:
                return seg['p_vaddr']
    return 0
