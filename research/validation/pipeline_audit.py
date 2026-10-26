"""
pipeline_audit.py — Empirical audit of systematic biases in our pipeline.

The principled approach: at each stage, measure what information is PRESERVED
vs LOST, and whether the loss is RANDOM or SYSTEMATIC.

Random loss = noise (manageable, averages out)
Systematic loss = bias (dangerous, skews all downstream results in one direction)

Five audit questions:
1. B matrix completeness: are constraint-based B rows the same as global_reads-based B rows?
2. Wall timeout distribution: which functions get cut off? Is there a pattern?
3. Loop truncation rate: how many functions hit exactly 4 loop iterations?
4. Constraint coverage: of all globals read, what fraction appear in any CBRANCH?
5. GF(2) rank vs real rank: how much does Boolean rank differ from SVD rank?
"""
import json, ctypes, re, sys, time, math
import numpy as np
from collections import defaultdict, Counter

from dynamic.pcode_sym import PCODESymEx
from dynamic.execute import DLLExecutor
from pe_utils import PE
from dynamic.implication_graph import extract_constraint_nodes

sys.stdout.reconfigure(line_buffering=True)

def gf2_rank(B_int):
    """
    Compute rank of binary matrix over GF(2) via Gaussian elimination.
    B_int: numpy bool/int array (m × n).
    Returns: rank (exact minimum functions that span the constraint space).
    """
    # Work with rows as integers (each row = bitmask of columns)
    m, n = B_int.shape
    # Pack rows into Python ints for fast XOR
    rows = []
    for i in range(m):
        val = 0
        for j in range(n):
            if B_int[i, j]:
                val |= (1 << j)
        rows.append(val)

    rank = 0
    pivot_col = 0
    for col in range(n):
        # Find pivot row
        pivot = None
        for row in range(rank, m):
            if rows[row] & (1 << col):
                pivot = row
                break
        if pivot is None:
            continue
        # Swap
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        # Eliminate
        for row in range(m):
            if row != rank and (rows[row] & (1 << col)):
                rows[row] ^= rows[rank]
        rank += 1

    return rank


def audit_dll(dll_path, ct_path, label, max_fns=200):
    print(f'\n{"="*60}')
    print(f'AUDIT: {label}')

    pe = PE(dll_path); ex = DLLExecutor(dll_path)
    rebase = ex.load_base - pe.image_base
    _WRITE = 0x80000000
    gr = [(pe.image_base+s['vrva'], pe.image_base+s['vrva']+s['vsize'])
          for s in pe.sections if s['vsize']>0 and (s['chars']&_WRITE)]
    with open(ct_path) as f:
        fns = [fn for fn in json.load(f)['functions']
               if re.search(r'DAT_[0-9a-fA-F]+', fn.get('pseudocode','') or '')][:max_fns]

    # Per-function audit data
    fn_global_reads = {}    # fn_name → set of global addresses (from pcode_sym)
    fn_constraint_vars = {} # fn_name → set of constraint variable names (from CBRANCHes)
    fn_wall_timeout   = []  # fn_names that hit wall timeout
    fn_loop_branches  = []  # fn_names with any LOOP_BRANCH
    fn_zero_reads     = []  # fn_names that had no global reads at all
    fn_reads_no_cbranch = [] # global reads but zero constraints

    for fn in fns:
        va = int(fn['va'],16); sz = fn['size']
        if sz < 4 or sz > 8000: continue
        try:
            code = bytes((ctypes.c_uint8*sz).from_address(va+rebase))
            exe  = PCODESymEx('x86:LE:64:default', code, va,
                              global_ranges=gr, verbose=False)
            r    = exe.run(va, initial_regs={'RSP':0x7FF00000,'RCX':0x1000},
                           max_steps=5000, wall_timeout=6.0)

            # Audit: information at each stage
            has_reads      = bool(r.global_reads)
            has_constraints= bool(r.constraints)
            timed_out      = any('WALL_TIMEOUT' in g for g in r.silent_guesses)
            has_loops      = any('LOOP_BRANCH'  in g for g in r.silent_guesses)

            if not has_reads:
                fn_zero_reads.append(fn['name'])
            if timed_out:
                fn_wall_timeout.append(fn['name'])
            if has_loops:
                fn_loop_branches.append(fn['name'])
            if has_reads and not has_constraints:
                fn_reads_no_cbranch.append(fn['name'])

            fn_global_reads[fn['name']] = set(r.global_reads.keys())

            # Extract constraint variable names
            nodes = extract_constraint_nodes(fn['name'], r.constraints,
                                             r.silent_guesses, canonicalize=True)
            constraint_vars = set()
            for node in nodes:
                constraint_vars |= node.global_vars
            fn_constraint_vars[fn['name']] = constraint_vars

        except Exception as e:
            fn_zero_reads.append(fn['name'])

    n_fns = len(fns)
    n_with_reads = len(fn_global_reads)
    n_constrained = len(fn_constraint_vars)

    print(f'  {n_fns} functions with DAT_ globals in pseudocode')
    print(f'  {n_with_reads} ({n_with_reads/max(1,n_fns):.0%}) produced any global reads')
    print(f'  {len(fn_zero_reads)} ({len(fn_zero_reads)/max(1,n_fns):.0%}) produced ZERO reads (dropped from B matrix)')

    print(f'\n  SYSTEMATIC BIAS AUDIT:')
    print(f'  Wall timeouts:   {len(fn_wall_timeout):4d} / {n_with_reads} = {len(fn_wall_timeout)/max(1,n_with_reads):.0%}')
    print(f'  Loop branches:   {len(fn_loop_branches):4d} / {n_with_reads} = {len(fn_loop_branches)/max(1,n_with_reads):.0%}')
    print(f'  Reads→no CBRANCH:{len(fn_reads_no_cbranch):4d} / {n_with_reads} = {len(fn_reads_no_cbranch)/max(1,n_with_reads):.0%}')
    print(f'  → These functions are INVISIBLE in our constraint-based B matrix')
    print(f'  → But they ARE real function-global relationships')

    # AUDIT 1: B matrix from global_reads vs B matrix from constraint vars
    all_reads_globals = sorted(set(g for gset in fn_global_reads.values() for g in gset))
    all_constr_globals = sorted(set(g for gset in fn_constraint_vars.values() for g in gset))
    overlap = set(all_reads_globals) & set(all_constr_globals)

    print(f'\n  B MATRIX COMPARISON (the critical audit):')
    print(f'  global_reads-based:   {len(fn_global_reads)} fns × {len(all_reads_globals)} globals')
    print(f'  constraint-based:     {len(fn_constraint_vars)} fns × {len(all_constr_globals)} globals')
    print(f'  Globals in both:      {len(overlap)} ({len(overlap)/max(1,len(all_reads_globals)):.0%} of reads globals)')
    print(f'  Globals only in reads:{len(set(all_reads_globals)-overlap)} — INVISIBLE to spectral test!')
    print(f'  → These are globals accessed but never used in conditional branches')
    print(f'  → May be pure state writes, logging, or non-branching reads')

    # Build both B matrices and compute GF(2) rank of each
    fn_names_ordered = sorted(fn_global_reads.keys())

    if len(fn_names_ordered) >= 5 and len(all_reads_globals) >= 5:
        # B from global_reads
        reads_idx = {g: i for i,g in enumerate(all_reads_globals)}
        B_reads = np.zeros((len(fn_names_ordered), len(all_reads_globals)), dtype=np.uint8)
        for row, fn_name in enumerate(fn_names_ordered):
            for g in fn_global_reads.get(fn_name, set()):
                if g in reads_idx:
                    B_reads[row, reads_idx[g]] = 1

        # B from constraints
        constr_idx = {g: i for i,g in enumerate(all_constr_globals)}
        fn_names_constr = sorted(fn_constraint_vars.keys())
        B_constr = np.zeros((len(fn_names_constr), len(all_constr_globals)), dtype=np.uint8)
        for row, fn_name in enumerate(fn_names_constr):
            for g in fn_constraint_vars.get(fn_name, set()):
                if g in constr_idx:
                    B_constr[row, constr_idx[g]] = 1

        # SVD rank (real rank)
        sv_reads  = np.linalg.svd(B_reads.astype(float), compute_uv=False)
        sv_constr = np.linalg.svd(B_constr.astype(float), compute_uv=False)
        real_rank_reads  = np.sum(sv_reads  > 0.5)
        real_rank_constr = np.sum(sv_constr > 0.5)

        # GF(2) rank (boolean rank) — exact minimum functions to span space
        print(f'\n  RANK AUDIT (GF(2) = exact, SVD = continuous):')
        if B_reads.shape[0] <= 200 and B_reads.shape[1] <= 500:
            gf2_reads = gf2_rank(B_reads)
            print(f'  B_reads:  SVD_rank={real_rank_reads}  GF2_rank={gf2_reads}  '
                  f'ratio={gf2_reads/max(1,real_rank_reads):.2f}')
        if B_constr.shape[0] <= 200 and B_constr.shape[1] <= 500:
            gf2_constr = gf2_rank(B_constr)
            print(f'  B_constr: SVD_rank={real_rank_constr}  GF2_rank={gf2_constr}  '
                  f'ratio={gf2_constr/max(1,real_rank_constr):.2f}')
            gf2_redundancy = 1 - gf2_constr / max(1, B_constr.shape[0])
            print(f'  GF(2) theoretical redundancy: {gf2_redundancy:.1%}  '
                  f'(vs empirical {0:.0%} from implication graph — gap = sampling undercount)')

        # Coverage ratio: what fraction of reads appear in constraints?
        mean_reads_per_fn = np.mean(B_reads.sum(axis=1))
        mean_constr_per_fn = B_constr.sum(axis=1).mean() if B_constr.shape[0]>0 else 0
        coverage = mean_constr_per_fn / max(1, mean_reads_per_fn)
        print(f'\n  COVERAGE: mean globals per function')
        print(f'  In global_reads: {mean_reads_per_fn:.1f}')
        print(f'  In constraints:  {mean_constr_per_fn:.1f}')
        print(f'  Coverage ratio:  {coverage:.0%} of accessed globals appear in CBRANCHes')
        print(f'  → {1-coverage:.0%} of global accesses are INVISIBLE to our spectral analysis')
        if coverage < 0.3:
            print(f'  ⚠ LOW: most global accesses are not constraint-bearing — B_constr is sparse')

    return {
        'label': label,
        'n_fns': n_fns, 'n_with_reads': n_with_reads,
        'wall_timeout_rate': len(fn_wall_timeout)/max(1,n_with_reads),
        'loop_branch_rate': len(fn_loop_branches)/max(1,n_with_reads),
        'reads_no_cbranch_rate': len(fn_reads_no_cbranch)/max(1,n_with_reads),
    }


TARGETS = [
    ('TESTS/real_world/windows/ws2_32/ws2_32.dll',
     'TESTS/real_world/windows/ws2_32/calltree.json',   'ws2_32'),
    ('TESTS/real_world/windows/advapi32/advapi32.dll',
     'TESTS/real_world/windows/advapi32/calltree.json', 'advapi32'),
    ('C:/Windows/System32/esent.dll',
     'TESTS/real_world/windows/esent/calltree.json',    'esent'),
    ('TESTS/real_world/windows/rpcrt4/rpcrt4.dll',
     'TESTS/real_world/windows/rpcrt4/calltree.json',   'rpcrt4'),
]

results = []
for dll, ct, lbl in TARGETS:
    try:
        r = audit_dll(dll, ct, lbl)
        results.append(r)
    except Exception as e:
        print(f'{lbl}: FAILED {e}')

print(f'\n{"="*65}')
print('SYSTEMATIC BIAS SUMMARY')
print(f'{"="*65}')
print(f'{"DLL":<12} {"WallTO%":>8} {"Loop%":>8} {"NoConstraint%":>14} {"DropRate%":>10}')
print('-'*65)
for r in results:
    drop = 1 - r['n_with_reads']/max(1,r['n_fns'])
    print(f'{r["label"]:<12} {r["wall_timeout_rate"]:>7.0%} {r["loop_branch_rate"]:>8.0%} '
          f'{r["reads_no_cbranch_rate"]:>13.0%} {drop:>10.0%}')

print(f'\nKEY: if WallTO% or NoConstraint% is high and SYSTEMATIC (same functions each run),')
print(f'     the B matrix is biased — not random noise but directional omission.')
print(f'     GF(2) rank vs SVD rank reveals the Boolean vs continuous rank gap.')
