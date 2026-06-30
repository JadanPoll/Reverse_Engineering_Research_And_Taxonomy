"""
dynamic/sweep.py — Classify all stripped test DLLs using dynamic/classify.

Gets export names from each test dir's ground_truth.KNOWN_VAS (keys = export names).
Runs classify.run(n_args=0) on every export, reports class + timing_cv.
Use this to measure pipeline accuracy and find classification gaps.

CLI:
    py -3.13 re_toolkit/dynamic/sweep.py
    py -3.13 re_toolkit/dynamic/sweep.py --filter prng_patterns crc_checksum
"""
import os, sys, importlib.util, traceback, argparse

_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(_here)
sys.path.insert(0, _root)
from dynamic.execute import DLLExecutor
from dynamic.classify import run as classify_run

TESTS_DIR = os.path.join(_root, "TESTS")

# What the dynamic layer should ideally emit for these wrapper-style test exports.
# All test exports are zero-arg wrappers that run internal logic and return a fixed
# pass/fail value — so "stateful" is the correct class (constant output, high timing_cv).
EXPECTED_CLASS = "stateful"


def load_ground_truth(test_dir):
    gt_path = os.path.join(TESTS_DIR, test_dir, "ground_truth.py")
    if not os.path.exists(gt_path):
        return None
    spec = importlib.util.spec_from_file_location("gt", gt_path)
    mod  = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


ap = argparse.ArgumentParser(description="Classify all stripped test DLLs")
ap.add_argument("--filter", nargs="*", metavar="DIR",
                help="Only run these test dirs (default: all)")
ap.add_argument("--n-args", type=int, default=0, metavar="N",
                help="Number of probe arguments (default: 0)")
opts = ap.parse_args()

rows = []
errors = []

test_dirs = sorted(d for d in os.listdir(TESTS_DIR)
                   if os.path.isdir(os.path.join(TESTS_DIR, d))
                   and d not in ("__pycache__",))

print(f"{'DLL':<32} {'EXPORT':<32} {'CLASS':<12} {'CONF':>5} {'TCV':>6}  STATUS")
print("-" * 100)

for test_dir in test_dirs:
    if opts.filter and test_dir not in opts.filter:
        continue
    stripped = os.path.join(TESTS_DIR, test_dir, f"{test_dir}_stripped.dll")
    if not os.path.exists(stripped):
        continue

    gt = load_ground_truth(test_dir)
    if gt is None or not hasattr(gt, "KNOWN_VAS") or not gt.KNOWN_VAS:
        print(f"{test_dir:<32} {'[no ground_truth]':<32}")
        continue

    try:
        ex = DLLExecutor(stripped)
    except Exception as e:
        print(f"{test_dir:<32} {'[LOAD FAIL]':<32}  {e}")
        errors.append((test_dir, "LOAD", str(e)))
        continue

    func_names = list(gt.KNOWN_VAS.keys())

    for name in func_names:
        try:
            result = classify_run(executor=ex, func=name, pseudocode="", n_args=opts.n_args)
            cls  = result.func_class
            conf = result.confidence
            tcv  = result.metrics.get("timing_cv", 0.0)
            ok   = cls == EXPECTED_CLASS
            status = "OK" if ok else f"WRONG(expected {EXPECTED_CLASS})"
            rows.append(dict(dir=test_dir, name=name, cls=cls, conf=conf,
                             tcv=tcv, ok=ok))
            print(f"{test_dir:<32} {name:<32} {cls:<12} {conf:>5.2f} {tcv:>6.3f}  {status}")
        except Exception as e:
            tb = traceback.format_exc().strip().splitlines()[-1]
            print(f"{test_dir:<32} {name:<32} {'CRASH':<12}  ---   ---   {tb:.70}")
            errors.append((test_dir, name, str(e)))
            rows.append(dict(dir=test_dir, name=name, cls="CRASH", conf=0,
                             tcv=0, ok=False))

print()
print("=" * 100)

total   = len(rows)
correct = sum(1 for r in rows if r["ok"])
crashes = sum(1 for r in rows if r["cls"] == "CRASH")
wrong   = [r for r in rows if not r["ok"] and r["cls"] != "CRASH"]

print(f"TOTAL: {total}  CORRECT: {correct}  WRONG: {len(wrong)}  CRASHES: {crashes}"
      f"  accuracy={correct/max(total,1):.1%}")

# Break down wrong classifications by what we actually got
if wrong:
    from collections import Counter
    got_counts = Counter(r["cls"] for r in wrong)
    print(f"\nWRONG breakdown (got instead of 'stateful'):")
    for cls, n in got_counts.most_common():
        examples = [r["dir"] + "/" + r["name"] for r in wrong if r["cls"] == cls][:3]
        print(f"  {cls:<12} x{n}  e.g. {examples}")

# High/low timing_cv within correct stateful classifications
stateful_rows = [r for r in rows if r["cls"] == "stateful"]
if stateful_rows:
    tcvs = sorted(r["tcv"] for r in stateful_rows)
    print(f"\nStateful timing_cv range: min={tcvs[0]:.3f}  median={tcvs[len(tcvs)//2]:.3f}  max={tcvs[-1]:.3f}")
    low_tcv = [r for r in stateful_rows if r["tcv"] < 0.3]
    if low_tcv:
        low_names = [r["dir"] + "/" + r["name"] for r in low_tcv]
        print(f"  Low tcv (<0.3) — borderline with 'constant': {low_names}")

if errors:
    print(f"\nERRORS ({len(errors)}):")
    for d, n, e in errors:
        print(f"  {d}/{n}: {e:.80}")
