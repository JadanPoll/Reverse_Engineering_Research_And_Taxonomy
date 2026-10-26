import sys, ctypes
sys.path.insert(0, ".")
from pe_utils import PE
from dynamic.vtable_resolver import VTableResolver

dll_path = r"TESTS\real_world\emulators\mgba\mgba_libretro.dll"
dll = ctypes.CDLL(dll_path)
load_base = dll._handle
pe = PE(dll_path)

print(f"image_base={pe.image_base:#x}  load_base={load_base:#x}")
print(f"rebase={load_base - pe.image_base:#x}")
print(f"\nSections:")
for s in pe.sections:
    prot = s["chars"]
    exec_flag  = bool(prot & 0x20000000)
    read_flag  = bool(prot & 0x40000000)
    write_flag = bool(prot & 0x80000000)
    runtime_va = load_base + s["vrva"]
    print(f"  {s['name']:<12} vrva={s['vrva']:#010x} vsize={s['vsize']:#010x} "
          f"chars={prot:#010x} X={exec_flag} R={read_flag} W={write_flag} "
          f"runtime={runtime_va:#x}")

# Check what _exec_ranges and _any_ranges contain
r = VTableResolver(dll_path, r"TESTS\real_world\emulators\mgba\calltree.json")
print(f"\nexec_ranges: {r._exec_ranges}")
print(f"any_ranges:  {r._any_ranges[:5]} ...")
print(f"\nTotal exec_ranges: {len(r._exec_ranges)}")
print(f"Total any_ranges:  {len(r._any_ranges)}")

# Test: is a known function VA in exec range?
# FUN_20c83f520 is the 51K function
test_va = 0x20c83f520
runtime_test = test_va + (load_base - pe.image_base)
print(f"\nTest function FUN_20c83f520:")
print(f"  ghidra_va={test_va:#x}")
print(f"  runtime_va={runtime_test:#x}")
print(f"  _in_dll_exec={r._in_dll_exec(runtime_test)}")
print(f"  _in_dll={r._in_dll(runtime_test)}")
