"""Test global_sim on mGBA DMA handler - requires GBA state struct normally from init."""
import sys
sys.path.insert(0, r"C:\Users\nathan37\Desktop\re_toolkit")
sys.path.insert(0, r"C:\Users\nathan37\Desktop\re_toolkit\dynamic")
from global_sim import GlobalTrackingSim, infer_required_globals, z3_solve_branch

dll_path      = r"TESTS\real_world\emulators\mgba\mgba_libretro.dll"
calltree_path = r"TESTS\real_world\emulators\mgba\calltree.json"

print("Loading GlobalTrackingSim...")
sim = GlobalTrackingSim(dll_path, calltree_path)

# Test Z3 solver first
print("\nZ3 branch solver test:")
for cond in ["!= 0", "& 1", "== 0", "> 0"]:
    result = z3_solve_branch(cond)
    print(f"  '{cond}': {result}")

# Find the DMA control handler
fn = sim._fns.get("FUN_20c8263d0")
if not fn:
    print("DMA handler not found, trying FUN_20c81de50 (SWI handler)...")
    fn = sim._fns.get("FUN_20c81de50")

if fn:
    spec = sim.classify(fn)
    print(f"\nFunction: {spec.fn_name}  size={spec.size}  purity={spec.purity}")
    print(f"simulable={spec.simulable}  ext_callees={spec.ext_callees[:3]}")

    # Run phase 1: what globals does this function read?
    print("\nPhase 1: Baseline run to discover global reads...")
    result = sim._run_with_tracking(spec, b'\x00'*64)
    print(f"  ok={result.ok}  coverage={len(result.coverage)} blocks")
    print(f"  global reads: {len(result.global_reads)}")
    for gr in result.global_reads[:5]:
        print(f"    addr={gr.address:#x}  size={gr.size}  stub_val={gr.stub_value}")

    if result.global_reads:
        print("\nPhase 2: Inferring required state via mutation...")
        required = infer_required_globals(sim, spec, verbose=True)
        print(f"\nRequired global state: {len(required)} addresses")
        for addr, val in sorted(required.items()):
            print(f"  {addr:#x} → {val}")
else:
    print("No suitable function found")
