import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "dynamic"))
from graph_metrics import annotate_calltree

with open("TESTS/real_world/openssl/calltree.json") as f:
    d = json.load(f)
fns = d["functions"]

va_set = {fn["va"] for fn in fns}
raw_seeds = {v for v in d.get("function_seeds", []) if v and v != "0x0"}
valid = raw_seeds & va_set
annotate_calltree(fns, seed_vas=valid if valid else None)

# The giant FUN_*
print("=== GIANT FUN_* ===")
for fn in fns:
    if fn["size"] > 10000 and fn["name"].startswith("FUN_"):
        print(f'{fn["name"]}: size={fn["size"]}  noise={fn.get("noise_cluster")}')
        print(f'  callers: {fn["calling_names"][:8]}')
        print(f'  callees: {fn["named_callees"][:8]}')
        print()

# Top ALG by betweenness
print("=== TOP ALG FUN_* by betweenness ===")
alg = [f for f in fns if not f.get("noise_cluster") and f["name"].startswith("FUN_")]
for fn in sorted(alg, key=lambda x: -x.get("betweenness", 0))[:20]:
    print(f'  bet={fn.get("betweenness",0):.4f}  k={fn.get("k_core",0):2d}  size={fn["size"]:6d}  {fn["name"]}')
    print(f'    callers: {fn["calling_names"][:4]}')
    print(f'    callees: {fn["named_callees"][:4]}')
