"""Debug: find exactly where FUN_20c8263d0 crashes with DRQ bit."""
import sys, ctypes
sys.path.insert(0, r"C:\Users\nathan37\Desktop\re_toolkit")
sys.path.insert(0, r"C:\Users\nathan37\Desktop\re_toolkit\dynamic")
from global_sim import GlobalTrackingSim
from slice_sim import INPUT_BASE, OUTPUT_BASE, STACK_BASE, STACK_SIZE
import unicorn as uc
import unicorn.x86_const as x86

dll_path = r"TESTS\real_world\emulators\mgba\mgba_libretro.dll"
ct_path  = r"TESTS\real_world\emulators\mgba\calltree.json"
sim = GlobalTrackingSim(dll_path, ct_path)
fn = sim._fns["FUN_20c8263d0"]
spec = sim.classify(fn)

env = sim._env_globals
input_data = b'\x00' * 256
env.reset_io(input_data)
env.set_registers({"rcx": INPUT_BASE, "rdx": 3, "r8": 0x800, "r9": 0})
mu = env.mu

last_addr = [0]
crash_info = []

def _hook_code(mu, addr, size, _):
    last_addr[0] = addr

def _hook_mem_invalid(mu, access, addr, size, value, _):
    rip = mu.reg_read(x86.UC_X86_REG_RIP)
    crash_info.append((access, addr, size, rip))
    # Map on demand and return 0
    try:
        mu.mem_map(addr & ~0xFFF, 0x1000)
    except: pass
    return True

mu.hook_add(uc.UC_HOOK_CODE, _hook_code)
mu.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED |
            uc.UC_HOOK_MEM_WRITE_UNMAPPED |
            uc.UC_HOOK_MEM_FETCH_UNMAPPED, _hook_mem_invalid)
env.stopped[0] = False

try:
    mu.emu_start(spec.va, spec.va + spec.size * 15, timeout=1_000_000, count=100_000)
    print("Emulation completed normally")
except uc.UcError as e:
    rip = mu.reg_read(x86.UC_X86_REG_RIP)
    gva = rip - sim._rebase
    fn_at = sim._fn_at(gva)
    name = fn_at["name"] if fn_at else "unknown"
    print(f"UcError: {e}")
    print(f"  RIP: {rip:#x}  Ghidra VA: {gva:#x}  ({name})")
    print(f"  Last code addr: {last_addr[0]:#x}  gva: {last_addr[0]-sim._rebase:#x}")

print(f"\nInvalid memory accesses triggered: {len(crash_info)}")
for access, addr, size, rip in crash_info[:5]:
    gva = addr - sim._rebase if sim._in_dll(addr) else addr
    print(f"  type={access}  addr={addr:#x}  gva={gva:#x}  size={size}  rip={rip:#x}")

print(f"\nSections in _env_globals mu (non-writable, mapped):")
pe = sim.pe
lb = sim.executor.load_base
for s in pe.sections:
    if not (s['chars'] & 0x80000000):  # non-writable
        gva_lo = pe.image_base + s['vrva']
        runtime_lo = lb + s['vrva']
        print(f"  {s['name']:<12} gva={gva_lo:#x} runtime={runtime_lo:#x} size={s['vsize']:#x}")
