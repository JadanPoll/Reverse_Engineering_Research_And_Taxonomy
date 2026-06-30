"""
analyze.py — H=1 status command for the RE toolkit.

Answers the canonical operational questions in ONE command:
  --status    Current analysis state: what's been done, what's a hole.
  --next N    Top N functions to investigate next (lowest compound scores).
  --floor     All named analysis floors (gaps the toolkit cannot close).
  --verify    Run _verify() on every module that has one.
  --holes     Print the full compound-score map (same as llm_name_functions --holes).

Usage:
    python analyze.py --status
    python analyze.py --next 10
    python analyze.py --floor
    python analyze.py --verify
    python analyze.py --holes

Design principle (from autonomous_llm_framework_fpga.md Principle 5):
  Any reasoning chain with H >= 3 must be compressed to a single entry point.
  "What should I work on next?" is the primary operational question.
  It used to require: know file names + have calltree.json + have names.json
  + run llm_name_functions --holes + interpret output.  That is H=4.
  This command compresses it to H=1.
"""

import os, sys, json, argparse, subprocess

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Load config ───────────────────────────────────────────────────────────────

try:
    from knowledge_bus import get_verify_hits as _get_verify_hits
    _HAS_KB = True
except Exception:
    _HAS_KB = False
    def _get_verify_hits(min_stability="EPHEMERAL"): return []

try:
    from ground_truth import (CALLTREE_JSON, NAMES_JSON, KNOWLEDGE_JSON,
                               TARGET_DLL, IMAGE_BASE, KNOWN_VAS, KNOWN_STRINGS)
    _GT_OK = True
except Exception as _e:
    print(f"[WARN] ground_truth.py not loaded: {_e}")
    CALLTREE_JSON  = os.path.join(_here, "ghidra_calltree.json")
    NAMES_JSON     = os.path.join(_here, "ghidra_names.json")
    KNOWLEDGE_JSON = os.path.join(_here, "ghidra_knowledge.json")
    TARGET_DLL = IMAGE_BASE = None
    KNOWN_VAS = KNOWN_STRINGS = {}
    _GT_OK = False

HOLE_THRESHOLD = 0.60

# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_json(path, label):
    if not os.path.exists(path):
        return None, f"[FLOOR:ARTIFACT_MISSING] {label} not found at {path}"
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f), None
    except Exception as e:
        return None, f"[FLOOR:ARTIFACT_CORRUPT] {label}: {e}"

def compute_compound_score(va, names, calltree_map, _visited=None):
    """HDG compound score: self_score * (0.60 + 0.40 * avg_callee_score)."""
    if _visited is None:
        _visited = set()
    if va in _visited:
        return 0.5
    _visited.add(va)

    item = names.get(va, {})
    if item.get("is_error_path") or item.get("is_runtime"):
        return 1.0

    self_score = float(item.get("understanding", 0.5))
    ct_entry   = calltree_map.get(va, {})
    callees    = ct_entry.get("called_vas", [])

    if not callees:
        return self_score

    callee_scores = []
    for cv in callees:
        callee_scores.append(compute_compound_score(cv, names, calltree_map, set(_visited)))

    avg = sum(callee_scores) / len(callee_scores)
    return round(self_score * (0.60 + 0.40 * avg), 3)

# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_status():
    print("=" * 64)
    print("RE TOOLKIT STATUS")
    print("=" * 64)

    # Ground truth
    print(f"\nground_truth.py : {'OK' if _GT_OK else 'MISSING'}")
    if _GT_OK:
        print(f"  Target        : {os.path.basename(TARGET_DLL)}")
        print(f"  ImageBase     : {IMAGE_BASE:#x}")
        print(f"  KNOWN_VAS     : {len(KNOWN_VAS)}")
        print(f"  KNOWN_STRINGS : {len(KNOWN_STRINGS)}")

    # Calltree
    calltree, err = _load_json(CALLTREE_JSON, "calltree")
    print(f"\nCalltree JSON   : ", end="")
    if err:
        print(err)
    else:
        n = calltree["count"]
        pcode = sum(len(f.get("pseudocode") or "") for f in calltree["functions"])
        floors = calltree.get("floors", [])
        print(f"OK  ({n} functions, {pcode:,} pseudocode chars)")
        if floors:
            for fl in floors:
                print(f"  [FLOOR:{fl['tag']}] count={fl.get('count','?')} -- {fl.get('note','')}")

    # Names
    names_data, err = _load_json(NAMES_JSON, "names")
    print(f"\nNames JSON      : ", end="")
    if err:
        print(err)
        names_data = {}
    else:
        n_total   = len(names_data)
        n_named   = sum(1 for v in names_data.values()
                        if v.get("suggested_name") and not v.get("suggested_name","").startswith("FUN_"))
        n_runtime = sum(1 for v in names_data.values() if v.get("is_runtime"))
        n_err     = sum(1 for v in names_data.values() if v.get("is_error_path"))
        avg_u     = (sum(float(v.get("understanding", 0)) for v in names_data.values())
                     / max(n_total, 1))
        print(f"OK  ({n_total} entries, {n_named} named, avg_understanding={avg_u:.2f})")
        print(f"  runtime/named_by_ghidra : {n_runtime}")
        print(f"  error_path              : {n_err}")

    # Knowledge
    kb, err = _load_json(KNOWLEDGE_JSON, "knowledge base")
    print(f"\nKnowledge base  : ", end="")
    if err:
        print(err)
    else:
        obs = kb.get("observations", [])
        qs  = kb.get("open_questions", [])
        print(f"OK  ({len(obs)} observations, {len(qs)} open questions)")

    # Three-way invariant status — cross-layer confirmation from knowledge_bus
    print(f"\nThree-way invariant:")
    if _HAS_KB:
        all_hits      = _get_verify_hits("EPHEMERAL")
        common_hits   = _get_verify_hits("COMMON")
        invariant_hits = _get_verify_hits("INVARIANT")
        print(f"  verify_hits total     : {len(all_hits)}")
        print(f"  COMMON  (2+ layers)   : {len(common_hits)}")
        print(f"  INVARIANT (all 3 layers) : {len(invariant_hits)}")
        for h in invariant_hits:
            print(f"    K={h['key'][:16]}...  layers={h['layers_seen']}  count={h['count']}")
        if common_hits and not invariant_hits:
            for h in common_hits:
                print(f"    K={h['key'][:16]}...  layers={h['layers_seen']}  (needs {3-len(set(h['layers_seen']))} more layer(s))")
        if not all_hits:
            print("  (no verify() hits recorded yet — run fractal_memscan or runtime_probe)")
    else:
        print("  knowledge_bus.py not loaded")

    # Compound score summary
    if calltree and names_data:
        calltree_map = {f["va"]: f for f in calltree["functions"]}
        scores = {}
        for f in calltree["functions"]:
            scores[f["va"]] = compute_compound_score(f["va"], names_data, calltree_map)

        holes = [(va, s) for va, s in scores.items() if s < HOLE_THRESHOLD]
        holes.sort(key=lambda x: x[1])
        print(f"\nCompound scores : {len(scores)} functions")
        print(f"  Holes (<{HOLE_THRESHOLD}) : {len(holes)}")
        if holes:
            worst = holes[:3]
            for va, s in worst:
                name = names_data.get(va, {}).get("suggested_name", "?")
                print(f"    {va}  score={s:.3f}  {name}")
            if len(holes) > 3:
                print(f"    ... and {len(holes)-3} more (use --next or --holes)")

    print()


def cmd_next(n):
    calltree, err1 = _load_json(CALLTREE_JSON, "calltree")
    names_data, err2 = _load_json(NAMES_JSON, "names")
    if err1 or not calltree:
        print(f"Cannot compute: {err1}")
        return
    names_data = names_data or {}

    calltree_map = {f["va"]: f for f in calltree["functions"]}
    scores = {}
    for f in calltree["functions"]:
        va = f["va"]
        item = names_data.get(va, {})
        if item.get("is_runtime") or item.get("is_error_path"):
            continue
        scores[va] = compute_compound_score(va, names_data, calltree_map)

    ranked = sorted(scores.items(), key=lambda x: x[1])[:n]
    print(f"Top {n} functions to investigate next (lowest compound scores):\n")
    for i, (va, score) in enumerate(ranked, 1):
        item = names_data.get(va, {})
        name  = item.get("suggested_name") or calltree_map[va].get("name", "?")
        tier  = item.get("tier_analyzed", 0)
        self_u = item.get("understanding", 0.0)
        n_callees = len(calltree_map[va].get("called_vas", []))
        print(f"  {i:2d}. {va}  compound={score:.3f}  self_u={self_u:.2f}"
              f"  tier=T{tier}  callees={n_callees}")
        print(f"      {name}")


def cmd_floor():
    calltree, _ = _load_json(CALLTREE_JSON, "calltree")
    print("Named analysis floors (structural gaps this toolkit cannot close):\n")

    # From calltree JSON
    if calltree:
        for fl in calltree.get("floors", []):
            print(f"  [FLOOR:{fl['tag']}]")
            print(f"    count : {fl.get('count', '?')}")
            print(f"    note  : {fl.get('note', '')}")
            print()
        # Per-function floors
        pf = {}
        for f in calltree["functions"]:
            for t in f.get("floors", []):
                pf[t] = pf.get(t, 0) + 1
        for tag, cnt in pf.items():
            print(f"  [FLOOR:{tag}] (per-function) count={cnt}")

    # Standard floors that always exist in headless analysis
    print()
    print("  [FLOOR:CALLEE_DEPTH_CUTOFF]")
    print(f"    note  : functions beyond depth {calltree.get('max_depth', '?') if calltree else '?'} not decompiled")
    print("  [FLOOR:DYNAMIC_BEHAVIOR]")
    print("    note  : Ghidra static analysis cannot observe runtime-only state (lazy init, heap alloc)")
    print("  [FLOOR:VERIFY_ORACLE_DIRECTION]")
    print("    note  : verify() checks K+IV against known (key1, guid) pairs -- does not recover K+IV from scratch")


def cmd_verify():
    print("Running _verify() on all re_toolkit modules:\n")
    # Maps module name to the args needed to trigger _verify()
    # ground_truth.py: runs _verify() when called with no args
    # pe_utils.py: needs --verify flag (no-arg runs CLI help)
    modules = [("ground_truth", []), ("pe_utils", ["--verify"]), ("knowledge_bus", [])]
    ok = 0
    fail = 0
    for mod, extra_args in modules:
        path = os.path.join(_here, f"{mod}.py")
        if not os.path.exists(path):
            print(f"  [SKIP] {mod}.py not found")
            continue
        result = subprocess.run(
            [sys.executable, path] + extra_args,
            capture_output=True, text=True, cwd=_here
        )
        if result.returncode == 0:
            lines = result.stdout.strip().splitlines()
            print(f"  [OK  ] {mod}.py")
            for line in lines:
                if line.strip():
                    print(f"         {line.strip()}")
            ok += 1
        else:
            print(f"  [FAIL] {mod}.py")
            print(f"         stdout: {result.stdout.strip()}")
            print(f"         stderr: {result.stderr.strip()}")
            fail += 1

    # Check artifact files exist
    print()
    for label, path in [("calltree.json", CALLTREE_JSON),
                         ("names.json",    NAMES_JSON),
                         ("knowledge.json", KNOWLEDGE_JSON)]:
        exists = os.path.exists(path)
        print(f"  {'[OK  ]' if exists else '[MISS]'} {label}  {path}")

    print(f"\nResult: {ok} passed, {fail} failed")


def cmd_holes():
    calltree, err1 = _load_json(CALLTREE_JSON, "calltree")
    names_data, err2 = _load_json(NAMES_JSON, "names")
    if err1 or not calltree:
        print(f"Cannot compute: {err1}")
        return
    names_data = names_data or {}

    calltree_map = {f["va"]: f for f in calltree["functions"]}
    rows = []
    for f in calltree["functions"]:
        va   = f["va"]
        item = names_data.get(va, {})
        is_rt  = item.get("is_runtime", False)
        is_err = item.get("is_error_path", False)
        cs = compute_compound_score(va, names_data, calltree_map)
        tag = ""
        if is_rt:  tag = "[rt] "
        if is_err: tag = "[err]"
        name = item.get("suggested_name") or f.get("name", "?")
        rows.append((cs, tag, va, name))

    rows.sort(key=lambda x: x[0])
    holes = sum(1 for cs, tag, _, _ in rows if not tag and cs < HOLE_THRESHOLD)
    print(f"Compound score map  ({len(rows)} functions, {holes} holes < {HOLE_THRESHOLD}):\n")
    for cs, tag, va, name in rows:
        marker = "!!" if (not tag and cs < HOLE_THRESHOLD) else "  "
        print(f"  {marker} {cs:.3f} {tag:<6s} {va}  {name[:60]}")


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--status",  action="store_true", help="Show overall analysis state")
    ap.add_argument("--next",    type=int, metavar="N", nargs="?", const=10,
                    help="Show top N functions to investigate next (default 10)")
    ap.add_argument("--floor",   action="store_true", help="Show named analysis floors")
    ap.add_argument("--verify",  action="store_true", help="Run _verify() on all modules")
    ap.add_argument("--holes",   action="store_true", help="Print full compound-score map")
    args = ap.parse_args()

    if not any(vars(args).values()):
        cmd_status()
    else:
        if args.status:  cmd_status()
        if args.next:    cmd_next(args.next)
        if args.floor:   cmd_floor()
        if args.verify:  cmd_verify()
        if args.holes:   cmd_holes()
