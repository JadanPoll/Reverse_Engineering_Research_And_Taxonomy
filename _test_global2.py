"""Crash-driven global state discovery test on mGBA DMA handler."""
import sys
sys.path.insert(0, r"C:\Users\nathan37\Desktop\re_toolkit")
sys.path.insert(0, r"C:\Users\nathan37\Desktop\re_toolkit\dynamic")
from global_sim import GlobalTrackingSim

dll_path = r"TESTS\real_world\emulators\mgba\mgba_libretro.dll"
ct_path  = r"TESTS\real_world\emulators\mgba\calltree.json"
sim = GlobalTrackingSim(dll_path, ct_path)

fn = sim._fns["FUN_20c8263d0"]
spec = sim.classify(fn)
print(f"Function: {spec.fn_name}  ext_callees={spec.ext_callees}")

print("\n=== Test 1: default params (all zeros) ===")
r = sim._run_with_tracking(spec, b'\x00'*256)
print(f"ok={r.ok}  blocks={len(r.coverage)}  global_reads={len(r.global_reads)}")

print("\n=== Test 2: DRQ bit set (param_2=3, param_3=0x800) ===")
r2 = sim._run_with_tracking(spec, b'\x00'*256, extra_regs={"rdx": 3, "r8": 0x800})
print(f"ok={r2.ok}  blocks={len(r2.coverage)}  global_reads={len(r2.global_reads)}")
_rb = sim.executor.load_base - sim.pe.image_base
for gr in r2.global_reads[:5]:
    gva = gr.address - _rb
    print(f"  runtime={gr.address:#x}  gva={gva:#x}  size={gr.size}  stub={gr.stub_value}")

print("\n=== Test 3: crash-driven discovery ===")
# Start with empty state, retry on each crash address
global_state = {}
for iteration in range(10):
    r3 = sim._run_with_tracking(spec, b'\x00'*256,
                                 global_stubs=global_state,
                                 extra_regs={"rdx": 3, "r8": 0x800})
    print(f"  iter={iteration}  ok={r3.ok}  blocks={len(r3.coverage)}"
          f"  new_globals={len(r3.global_reads)}")
    if r3.ok or not r3.global_reads:
        break
    # Retry: set each new global read to 0x1 (non-null)
    from slice_sim import INPUT_BASE
    for gr in r3.global_reads:
        if gr.address not in global_state:
            # Pointer globals need valid mapped addresses, not just 1.
            # INPUT_BASE is a valid mapped region — gives the function a non-null
            # struct pointer that won't crash on dereference.
            val = INPUT_BASE if gr.size >= 8 else 1
            global_state[gr.address] = val
            print(f"    -> global: {gr.address:#x}  size={gr.size}  value={val:#x}")

print(f"\nFinal required global state: {len(global_state)} addresses")
print(f"Final coverage: {len(r3.coverage)} basic blocks")
