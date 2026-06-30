"""
_naming_run.py — Systematic naming pass across all real-world calltrees.
For each library: apply graph metrics, show signal functions ranked by graph_rank,
read pseudocode of top FUN_* and attempt naming. Record H-score.
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "dynamic"))
from graph_metrics import annotate_calltree

REAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "TESTS", "real_world")
LIBS = ["zlib", "mbedtls"]  # focus on ones we haven't analyzed yet

for lib in LIBS:
    path = os.path.join(REAL, lib, "calltree.json")
    if not os.path.exists(path):
        print(f"{lib}: NO CALLTREE"); continue

    with open(path) as f:
        d = json.load(f)
    fns = d["functions"]
    va_set = {fn["va"] for fn in fns}
    raw_seeds  = {v for v in d.get("function_seeds", []) if v and v != "0x0"}
    valid_seeds = raw_seeds & va_set
    annotate_calltree(fns, seed_vas=valid_seeds if valid_seeds else None)

    alg = [f for f in fns if not f.get("noise_cluster") and f["name"].startswith("FUN_")]
    alg_sorted = sorted(alg, key=lambda x: -x.get("graph_rank", 0))

    print(f"\n{'='*70}")
    print(f"  {lib.upper()} — {len(fns)} total, {len(alg)} ALG FUN_*, noise={sum(1 for f in fns if f.get('noise_cluster'))}")
    print(f"{'='*70}")
    print(f"\nTop ALG FUN_* by graph_rank:")
    for fn in alg_sorted[:15]:
        callers = fn.get("calling_names", [])[:3]
        callees = fn.get("named_callees", [])[:3]
        print(f"  rank={fn.get('graph_rank',0):.4f}  k={fn.get('k_core',0)}  "
              f"bet={fn.get('betweenness',0):.4f}  size={fn['size']:5d}  "
              f"in={len(fn.get('calling_names',[]))}  {fn['name']}")
        if callers: print(f"    callers: {callers}")
        if callees: print(f"    callees: {callees}")
