"""
leverage_gf2.py — Two tests from the critique:

1. LEVERAGE SCORES: ℓᵢ = ‖Uᵢ‖² from SVD (5 lines).
   Shape of distribution predicts T_α via U-statistic/Hoeffding decomposition:
   - Few high leverage + many near-zero → concentrated → T_α << -0.5 (advapi32)
   - Roughly uniform → diffuse → T_α ≈ -0.5 (CLT case, esent)
   - Bimodal (sparse high-leverage) → heavy-tailed pairs → T_α > 0 (ws2_32)

2. GF(2) RANK STAIRCASE: exact zero-noise analog of redundancy convergence curve.
   rank_{GF(2)}(B_N) as N increases — shows which functions are truly new (rank++)
   vs GF(2) combinations of prior functions (rank stays same).
   For esent: staircase should show same phase structure as the bootstrap curve.

3. HOEFFDING FIRST-ORDER TERM: h₁(f) = E_g[k(f,g)] - T(F)
   where k(f,g) = implications between f's and g's constraints.
   Var[h₁] ≠ 0 → super-CLT convergence (advapi32).
   h₁ ≈ 0 everywhere → second-order U-stat → CLT.
   Heavy-tailed pairs → stable law → T_α > 0 (ws2_32).

Reference: Hoeffding (1948), U-Statistics. de la Peña-Lai-Shao, Self-normalized processes.
"""
import json, ctypes, re, sys, time, math
import numpy as np
from collections import defaultdict

from dynamic.pcode_sym import PCODESymEx
from dynamic.execute import DLLExecutor
from pe_utils import PE
from dynamic.implication_graph import extract_constraint_nodes, build_implication_graph

sys.stdout.reconfigure(line_buffering=True)

KNOWN_ALPHA = {
    'ws2_32': +0.45, 'advapi32': -2.04, 'esent': -0.36, 'rpcrt4': -0.33
}

def name_to_addr(name):
    if name.startswith('g_'):
        try: return int(name[2:], 16)
        except: return None
    if name.startswith('f_'):
        parts = name[2:].split('_')
        for p in parts:
            try: return int(p, 16)
            except: continue
    return None

# ── GF(2) incremental rank ────────────────────────────────────────────────────

def gf2_rank_incremental(B_binary):
    """Compute GF(2) rank as each row is added. Returns list of ranks (staircase).
    O(N × n²) in worst case, but fast for sparse rows via early termination.
    Each rank increase = this function is GF(2)-independent of all prior ones.
    """
    m, n = B_binary.shape
    pivots = {}   # col → row_int (the current basis)
    ranks = []
    rank = 0

    for i in range(m):
        row = B_binary[i].copy()
        for col in sorted(pivots.keys()):
            if row[col]:
                row ^= pivots[col]

        # Find first non-zero position
        nz = np.where(row)[0]
        if len(nz) > 0:
            rank += 1
            pivots[nz[0]] = row.copy()

        ranks.append(rank)
    return ranks

# ── Leverage score analysis ───────────────────────────────────────────────────

def leverage_analysis(B, fn_names):
    """Compute leverage scores and fit power-law decay.
    ℓᵢ = ‖Uᵢ‖² using ONLY the top-k singular vectors (k = rank).
    ∑ℓᵢ = rank(B) — leverage scores sum to rank. (Bug fix: use U[:,:k] not full U)
    Decay exponent β from log-log fit.
    """
    m, n = B.shape
    U, S, Vt = np.linalg.svd(B, full_matrices=False)
    # FIX: only use rank-k singular vectors, not all min(m,n)
    # Using all would give ∑ℓᵢ = n (columns) instead of rank — wrong
    k = int(np.sum(S > 0.5))   # rank = number of non-zero singular values
    U_k = U[:, :k]
    leverage = np.sum(U_k**2, axis=1)   # ℓᵢ = ‖Uᵢ‖²  now ∑ℓᵢ = k = rank ✓

    # Verify: ∑ℓᵢ = rank(B) (within numerical precision)
    rank_est = np.sum(S > 0.5)
    ls_sum   = leverage.sum()

    # Sort descending, fit power law
    ls_sorted = np.sort(leverage)[::-1]
    x = np.log(np.arange(1, len(ls_sorted)+1))
    y = np.log(ls_sorted + 1e-10)
    beta_fit = -np.polyfit(x, y, 1)[0]  # slope in log-log → decay exponent

    # Characterize shape
    ls_high = np.sum(leverage > 0.5)   # "high-leverage" functions
    ls_zero = np.sum(leverage < 0.01)  # "invisible" functions
    bimodal_score = (ls_high + ls_zero) / m  # fraction in extreme bins

    return {
        'leverage': leverage,
        'ls_sorted': ls_sorted,
        'rank': rank_est,
        'ls_sum': ls_sum,
        'beta': beta_fit,
        'n_high': ls_high,
        'n_zero': ls_zero,
        'bimodal_score': bimodal_score,
        'U': U, 'S': S,
        'fn_names': fn_names,
    }

# ── Hoeffding first-order term ────────────────────────────────────────────────

def hoeffding_h1(all_nodes, fn_names, max_pairs=500):
    """Estimate h₁(f) = E_g[k(f,g)] - T(F) for each function f.
    k(f,g) = implication rate between f's and g's constraints.
    CENTERING IS CRITICAL: h₁ must be centered by subtracting overall mean T(F).
    Bug fix: original computed E_g[k(f,g)] (raw mean), not E_g[k(f,g)] - T(F).
    Var[h₁] ≠ 0 → super-CLT. h₁ ≈ 0 → CLT. Heavy-tailed → stable law.
    """
    from dynamic.implication_graph import classify_constraint_field_type

    # Group nodes by function
    fn_node_map = defaultdict(list)
    for node in all_nodes:
        fn_node_map[node.fn_name].append(node)

    fn_list = [f for f in fn_names if f in fn_node_map]
    if len(fn_list) < 5:
        return None

    # Estimate k(f,g) for random pairs
    from dynamic.implication_graph import check_implication
    import random
    rng = random.Random(42)

    h1_vals = {}
    sample_size = min(20, len(fn_list)-1)

    for fn in fn_list[:30]:  # limit to 30 fns for speed
        fn_nodes = fn_node_map[fn]
        if not fn_nodes:
            continue
        others = [f for f in fn_list if f != fn]
        sampled = rng.sample(others, min(sample_size, len(others)))
        k_vals = []
        for other_fn in sampled:
            other_nodes = fn_node_map[other_fn]
            if not other_nodes:
                continue
            pairs_checked = 0
            implications = 0
            for node_i in fn_nodes[:5]:
                for node_j in other_nodes[:5]:
                    if node_i.global_vars & node_j.global_vars:
                        try:
                            if check_implication(node_i.formula, node_j.formula, 3000):
                                implications += 1
                            pairs_checked += 1
                        except: pass
            k_vals.append(implications / max(1, pairs_checked))
        if k_vals:
            h1_vals[fn] = np.mean(k_vals)

    # FIX: CENTER h₁ by subtracting overall mean T(F)
    # h₁(f) = E_g[k(f,g)] - T(F)  where T(F) = E_{f,g}[k(f,g)]
    if h1_vals:
        T_F = np.mean(list(h1_vals.values()))  # overall mean implication rate
        for fn in h1_vals:
            h1_vals[fn] -= T_F  # center: now Var[h₁] measures DEVIATION from mean

    h1_arr = np.array(list(h1_vals.values()))
    return h1_arr

# ── Main ──────────────────────────────────────────────────────────────────────

def analyze(dll_path, ct_path, label, max_fns=200):
    print(f'\n{"="*62}')
    print(f'{label}  T_α={KNOWN_ALPHA.get(label, "?")}')

    pe = PE(dll_path); ex = DLLExecutor(dll_path)
    rebase = ex.load_base - pe.image_base
    _WRITE = 0x80000000
    gr = [(pe.image_base+s['vrva'], pe.image_base+s['vrva']+s['vsize'])
          for s in pe.sections if s['vsize']>0 and (s['chars']&_WRITE)]
    with open(ct_path) as f:
        fns = [fn for fn in json.load(f)['functions']
               if re.search(r'DAT_[0-9a-fA-F]+', fn.get('pseudocode','') or '')][:max_fns]

    fn_reads = {}; fn_constrs = {}; all_nodes = []
    for fn in fns:
        va = int(fn['va'],16); sz = fn['size']
        if sz < 4 or sz > 8000: continue
        try:
            code = bytes((ctypes.c_uint8*sz).from_address(va+rebase))
            exe  = PCODESymEx('x86:LE:64:default', code, va,
                              global_ranges=gr, verbose=False)
            r    = exe.run(va, initial_regs={'RSP':0x7FF00000,'RCX':0x1000},
                           max_steps=5000, wall_timeout=6.0)
            if r.global_reads:
                fn_reads[fn['name']] = set(r.global_reads.keys())
            nodes = extract_constraint_nodes(fn['name'], r.constraints,
                                             r.silent_guesses, canonicalize=True)
            addrs = {name_to_addr(v) for node in nodes for v in node.global_vars}
            addrs.discard(None)
            if addrs:
                fn_constrs[fn['name']] = addrs
            all_nodes.extend(nodes)
        except: pass

    all_globals = sorted(set(a for s in fn_reads.values() for a in s) |
                         set(a for s in fn_constrs.values() for a in s))
    all_fns = sorted(set(fn_reads) | set(fn_constrs))
    if len(all_fns) < 5 or len(all_globals) < 5:
        print('  Too few data'); return None

    g_idx = {g: i for i,g in enumerate(all_globals)}
    m, n  = len(all_fns), len(all_globals)

    B = np.zeros((m, n), dtype=np.uint8)
    for row, fn in enumerate(all_fns):
        for a in (fn_reads.get(fn, set()) | fn_constrs.get(fn, set())):
            if a in g_idx: B[row, g_idx[a]] = 1

    print(f'  B: {m} fns × {n} globals')

    # ── 1. LEVERAGE SCORES ───────────────────────────────────────────────────
    lev = leverage_analysis(B.astype(float), all_fns)
    ls = lev['ls_sorted']

    print(f'\n  LEVERAGE SCORES:')
    print(f'  rank={lev["rank"]}  ∑ℓᵢ={lev["ls_sum"]:.2f}  '
          f'(should ≈ rank={lev["rank"]})')
    print(f'  top5: {[f"{x:.3f}" for x in ls[:5]]}')
    print(f'  n_high(ℓ>0.5): {lev["n_high"]}  n_zero(ℓ<0.01): {lev["n_zero"]}')
    print(f'  decay_β={lev["beta"]:.2f}  bimodal_score={lev["bimodal_score"]:.2f}')

    # Predict T_α from leverage shape
    if lev['n_high'] >= 1 and ls[0] > 0.8:
        pred = 'CONCENTRATED → super-CLT → T_α << -0.5'
    elif lev['bimodal_score'] > 0.5:
        pred = 'BIMODAL → heavy-tailed pairs → T_α > 0'
    else:
        pred = 'UNIFORM → CLT → T_α ≈ -0.5'
    print(f'  Prediction: {pred}')

    # ── 2. GF(2) RANK STAIRCASE ──────────────────────────────────────────────
    print(f'\n  GF(2) RANK STAIRCASE:')
    t0 = time.perf_counter()
    ranks = gf2_rank_incremental(B)
    elapsed = time.perf_counter() - t0
    final_rank = ranks[-1]
    gf2_redundancy = 1 - final_rank / m

    # Find the "jumps" — functions that increase the rank
    jumps = [i for i in range(1, len(ranks)) if ranks[i] > ranks[i-1]]
    jump_density_early = sum(1 for j in jumps if j < m//3) / max(1, m//3)
    jump_density_late  = sum(1 for j in jumps if j >= 2*m//3) / max(1, m//3)

    print(f'  Final GF(2) rank: {final_rank}/{m} = {gf2_redundancy:.0%} redundant ({elapsed:.1f}s)')
    print(f'  Jump density early(N<{m//3}): {jump_density_early:.2f}/fn')
    print(f'  Jump density late(N>{2*m//3}): {jump_density_late:.2f}/fn')

    # Show rank at key N values
    checkpoints = [10, 25, 50, 100, 150, 200]
    rank_at = [(n, ranks[min(n-1, m-1)]) for n in checkpoints if n <= m]
    print(f'  Rank progression: {[(n, r) for n,r in rank_at]}')

    # Phase transition detection: where does rank growth accelerate?
    if m > 50:
        rank_arr = np.array(ranks)
        growth = np.diff(rank_arr.astype(float))  # 1 where rank increased
        window = max(10, m//20)
        rolling = np.convolve(growth, np.ones(window)/window, mode='valid')
        peak_n = np.argmax(rolling) + window//2
        print(f'  Peak rank-growth at N≈{peak_n} (staircase "phase transition")')

    # ── 3. HOEFFDING h₁ DISTRIBUTION ─────────────────────────────────────────
    print(f'\n  HOEFFDING FIRST-ORDER TERM (h₁ distribution):')
    h1 = hoeffding_h1(all_nodes, all_fns, max_pairs=300)
    if h1 is not None and len(h1) > 3:
        h1_var = np.var(h1)
        h1_max = np.max(np.abs(h1))
        print(f'  h₁ variance: {h1_var:.6f}  h₁ max: {h1_max:.4f}')
        if h1_var > 0.001:
            print(f'  Var[h₁] >> 0 → super-CLT convergence predicted (T_α << -0.5)')
        else:
            print(f'  Var[h₁] ≈ 0 → second-order U-statistic dominates → T_α ≈ -0.5')
    else:
        print('  Too few constraint pairs for h₁ estimation')

    return {
        'label': label, 'm': m, 'n': n,
        'leverage_beta': lev['beta'],
        'n_high': lev['n_high'],
        'bimodal_score': lev['bimodal_score'],
        'gf2_rank': final_rank,
        'gf2_redundancy': gf2_redundancy,
        'peak_n': peak_n if m > 50 else None,
        'alpha': KNOWN_ALPHA.get(label),
        'ls_top3': ls[:3].tolist(),
        'h1_var': float(np.var(h1)) if h1 is not None and len(h1) > 3 else None,
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
        r = analyze(dll, ct, lbl)
        if r: results.append(r)
    except Exception as e:
        print(f'{lbl}: FAILED {e}')

# Summary table
print(f'\n{"="*70}')
print('SUMMARY — Leverage score shape predicts T_α via U-statistic theory')
print(f'{"="*70}')
print(f'{"DLL":<12} {"ls_β":>6} {"n_high":>7} {"bimod":>7} {"gf2_red":>8} {"h1_var":>9} {"T_α":>8}')
print('-'*65)
for r in sorted(results, key=lambda x: x['alpha'] or 0):
    ta = f'{r["alpha"]:+.2f}' if r['alpha'] else '?'
    h1 = f'{r["h1_var"]:.5f}' if r['h1_var'] is not None else 'N/A'
    print(f'{r["label"]:<12} {r["leverage_beta"]:>6.2f} {r["n_high"]:>7} '
          f'{r["bimodal_score"]:>7.2f} {r["gf2_redundancy"]:>7.0%} {h1:>9} {ta:>8}')

from scipy import stats as sp_stats
print('\nCORRELATION TESTS:')
for key, name in [('leverage_beta', 'leverage_β'), ('bimodal_score', 'bimodal'),
                   ('h1_var', 'Hoeffding_h1_var')]:
    vals = [r[key] for r in results if r.get(key) is not None and r['alpha'] is not None]
    alphas = [r['alpha'] for r in results if r.get(key) is not None and r['alpha'] is not None]
    if len(vals) >= 3:
        corr, p = sp_stats.pearsonr(vals, alphas)
        star = '★' if abs(corr) > 0.8 else ' '
        print(f'{star} corr({name:20s}, T_α) = {corr:+.3f}  p={p:.3f}')

print('\nHOEFFDING INTERPRETATION:')
print('  h₁ variance >> 0 → first-order term dominates → super-CLT (T_α << -0.5)')
print('  h₁ variance ≈ 0 → second-order dominates → CLT (T_α ≈ -0.5)')
print('  For ws2_32: if heavy-tailed pairs → stable law → T_α > 0')
print('  Power-law leverage: steep decay_β > 1 → concentrated → advapi32')
print('                      flat decay_β < 0.5 → diffuse → esent/rpcrt4')
