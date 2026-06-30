"""
redundancy_convergence.py — How many functions needed before redundancy stabilizes?

The practical question: when can you STOP observing functions and trust the redundancy
estimate? This directly answers the LLM budget question for binary exploration.

Method: run pcode_sym on N functions, compute redundancy, vary N from small to large.
Plot redundancy(N) and find the knee where it stops growing significantly.

Key insight from information theory: if redundancy is measuring a real structural
property, it should converge as N → enough_functions. Convergence rate tells you
how many independent observations are needed to characterize the init spec complexity.
"""
import json, ctypes, re, sys, time, math
from dynamic.pcode_sym import PCODESymEx
from dynamic.execute import DLLExecutor
from pe_utils import PE
from dynamic.implication_graph import extract_constraint_nodes, build_implication_graph
from collections import defaultdict

sys.stdout.reconfigure(line_buffering=True)

TOTAL_BUDGET  = 500          # total function runs across all sample sizes
SAMPLE_SIZES  = [10, 25, 50, 100, 200, 500]  # N values to test
# Repetitions per sample size = TOTAL_BUDGET // N, but at least 2, at most 50
def n_reps(n): return max(2, min(50, TOTAL_BUDGET // n))

import random as _random

def convergence_curve(dll_path, ct_path, label, max_fns=500, max_pairs=800, seed=42):
    """
    Bootstrap redundancy convergence.
    For each sample size N, draw n_reps(N) random samples of N functions,
    compute redundancy for each, report mean ± std.

    Total compute budget: fixed at ~TOTAL_BUDGET function runs,
    allocated across sample sizes (small N gets many repetitions,
    large N gets few but more accurate estimates).

    Statistical property: std should decay as 1/sqrt(N) under CLT.
    Deviation from 1/sqrt(N) decay reveals non-random structure.
    Convergence criterion: std/mean < 0.10 (relative standard error < 10%).
    """
    pe = PE(dll_path)
    ex = DLLExecutor(dll_path)
    rebase = ex.load_base - pe.image_base
    _WRITE = 0x80000000
    gr = [(pe.image_base+s['vrva'], pe.image_base+s['vrva']+s['vsize'])
          for s in pe.sections if s['vsize']>0 and (s['chars']&_WRITE)]

    with open(ct_path) as f:
        all_fns = [fn for fn in json.load(f)['functions']
                   if re.search(r'DAT_[0-9a-fA-F]+', fn.get('pseudocode','') or '')]

    # Pre-collect constraint nodes from ALL available functions (up to max_fns)
    # Group nodes by function index so we can subsample by function
    rng = _random.Random(seed)
    pool_fns = all_fns[:max_fns]
    fn_nodes = {}   # fn_index → list of ConstraintNodes

    print(f'Pre-collecting from {len(pool_fns)} functions...', flush=True)
    t0 = time.perf_counter()
    for i, fn in enumerate(pool_fns):
        va = int(fn['va'],16); sz = fn['size']
        if sz < 4 or sz > 8000: continue
        if i % 150 == 0:
            print(f'  {i}/{len(pool_fns)}...', file=sys.stderr, flush=True)
        try:
            code = bytes((ctypes.c_uint8*sz).from_address(va+rebase))
            exe  = PCODESymEx('x86:LE:64:default', code, va,
                              global_ranges=gr, verbose=False)
            r    = exe.run(va, initial_regs={'RSP':0x7FF00000,'RCX':0x1000},
                           max_steps=5000, wall_timeout=6.0)
            nodes = extract_constraint_nodes(fn['name'], r.constraints,
                                             r.silent_guesses, canonicalize=True)
            if nodes:
                fn_nodes[i] = nodes
        except:
            pass

    elapsed = time.perf_counter() - t0
    valid_fn_indices = sorted(fn_nodes.keys())
    total_nodes = sum(len(v) for v in fn_nodes.values())
    print(f'  {len(valid_fn_indices)} fns with constraints, {total_nodes} total nodes ({elapsed:.0f}s)', flush=True)

    if len(valid_fn_indices) < 10:
        print(f'{label}: too few functions'); return {}

    results = {}
    print(f'\n{label} — bootstrap convergence (total budget ~{TOTAL_BUDGET} fn-runs):')
    print(f'  {"N":>5}  {"reps":>5}  {"mean":>8}  {"std":>8}  {"CV%":>6}  {"min":>7}  {"max":>7}  Status')
    print(f'  {"-"*5}  {"-"*5}  {"-"*8}  {"-"*8}  {"-"*6}  {"-"*7}  {"-"*7}  {"-"*15}')

    for n in SAMPLE_SIZES:
        if n > len(valid_fn_indices):
            continue
        reps = n_reps(n)
        sample_reds = []

        for rep in range(reps):
            # Random sample of N functions (without replacement)
            sampled_indices = rng.sample(valid_fn_indices, n)
            subset_nodes = []
            for idx in sampled_indices:
                subset_nodes.extend(fn_nodes[idx])

            if len(subset_nodes) < 3:
                continue

            impl = build_implication_graph(subset_nodes, max_pairs=max_pairs,
                                           timeout_per_ms=1000, verbose=False)
            sample_reds.append(impl.redundancy)

        if not sample_reds:
            continue

        mean_r = sum(sample_reds) / len(sample_reds)
        var_r  = sum((r - mean_r)**2 for r in sample_reds) / max(1, len(sample_reds)-1)
        std_r  = math.sqrt(var_r)
        cv     = (std_r / mean_r * 100) if mean_r > 0 else 0
        min_r  = min(sample_reds)
        max_r  = max(sample_reds)

        # Status: converged if CV < 10%
        if cv < 10:
            status = 'CONVERGED ✓'
        elif cv < 25:
            status = 'stabilizing'
        else:
            status = 'noisy'

        print(f'  {n:>5}  {reps:>5}  {mean_r:>7.1%}  {std_r:>7.1%}  {cv:>5.1f}%  '
              f'{min_r:>6.1%}  {max_r:>6.1%}  {status}', flush=True)

        results[n] = {
            'mean': mean_r, 'std': std_r, 'cv': cv,
            'min': min_r, 'max': max_r, 'reps': reps,
        }

    # Find convergence knee: smallest N where CV < 10%
    converged_at = next((n for n in SAMPLE_SIZES if n in results and results[n]['cv'] < 10), None)
    if converged_at:
        final_mean = results[max(k for k in results)][ 'mean']
        print(f'  → CONVERGED at N={converged_at} (CV<10%)  final_mean={final_mean:.1%}')
    else:
        print(f'  → NOT CONVERGED within budget (CV still >10% at N={max(results)})')

    # Test CLT decay: does std ∝ 1/sqrt(N)?
    ns   = [n for n in SAMPLE_SIZES if n in results]
    stds = [results[n]['std'] for n in ns]
    if len(ns) >= 3:
        # Fit log(std) = a - 0.5*log(N) under CLT
        import math as _m
        log_n = [_m.log(n) for n in ns]
        log_s = [_m.log(max(s, 1e-6)) for s in stds]
        mn_n, mn_s = sum(log_n)/len(log_n), sum(log_s)/len(log_s)
        cov = sum((log_n[i]-mn_n)*(log_s[i]-mn_s) for i in range(len(ns)))
        var = sum((x-mn_n)**2 for x in log_n)
        slope = cov/var if var > 0 else 0
        print(f'  CLT check: log(std) vs log(N) slope={slope:.2f} '
              f'(expected -0.5 under CLT; deviation = non-random structure)')

    return results


TARGETS = [
    ('TESTS/real_world/windows/ws2_32/ws2_32.dll',
     'TESTS/real_world/windows/ws2_32/calltree.json',
     'ws2_32 (ZIPF+INDEP, ~0%)'),
    ('TESTS/real_world/windows/advapi32/advapi32.dll',
     'TESTS/real_world/windows/advapi32/calltree.json',
     'advapi32 (ZIPF+COUPLED, 5.7%)'),
    ('C:/Windows/System32/esent.dll',
     'TESTS/real_world/windows/esent/calltree.json',
     'esent (ZIPF+COUPLED, 9.2%)'),
    ('TESTS/real_world/windows/rpcrt4/rpcrt4.dll',
     'TESTS/real_world/windows/rpcrt4/calltree.json',
     'rpcrt4 (CHAIN+COUPLED, 15.9%)'),
    ('TESTS/real_world/emulators/mgba/mgba_libretro.dll',
     'TESTS/real_world/emulators/mgba/calltree.json',
     'mGBA (ZIPF+COUPLED, 7.9%)'),
]

all_curves = {}
for dll, ct, lbl in TARGETS:
    try:
        curve = convergence_curve(dll, ct, lbl)
        all_curves[lbl.split()[0]] = curve
    except Exception as e:
        print(f'{lbl}: FAILED {e}')

# Cross-DLL summary: at what N does each DLL converge?
print()
print('='*65)
print('CONVERGENCE SUMMARY')
print('='*65)
print('Question: how many functions until redundancy is within 1% of final?')
print()
for name, curve in all_curves.items():
    if not curve: continue
    reds = sorted(curve.items())
    final = reds[-1][1]['redundancy'] if reds else 0
    # Find first N where redundancy is within 1% of final
    converged_at = None
    for n, v in reds:
        if abs(v['redundancy'] - final) < 0.01:
            converged_at = n
            break
    print(f'  {name:<12}: final={final:.1%}  converged_at={converged_at} fns  '
          f'(within 1% of {final:.1%})')
