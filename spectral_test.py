"""
spectral_test.py — Test the spectral theory of program structure.

Hypothesis: the function × global incidence matrix B encodes all the
structural information we've been computing manually, via its SVD.

Specifically testing:
1. M-P deviation: do coupled DLLs deviate more from Marchenko-Pastur?
2. Spectral gap (σ₂/σ₁ from B's SVD) predicts T_α convergence exponent
3. Fiedler value of co-access graph Laplacian predicts T_α

We have T_α from bootstrap for: ws2_32(+0.45), advapi32(-2.04),
esent(-0.36), rpcrt4(-0.33).

Mathematical framework:
- B = m×n binary matrix (m functions, n globals accessed)
- SVD: B = U Σ Vᵀ, singular values σ₁ ≥ σ₂ ≥ ... ≥ 0
- Marchenko-Pastur: for random B with ratio γ=n/m, eigenvalues of BᵀB/m
  concentrate on [(1-√γ)², (1+√γ)²]
- Spectral gap: 1 - σ₂/σ₁ (normalized). Large gap = fast mixing = large |T_α|
- Fiedler value λ₂ of normalized co-access Laplacian
"""
import json, ctypes, re, sys, time, math
import numpy as np
from scipy import stats as sp_stats
import networkx as nx
from collections import defaultdict

from dynamic.pcode_sym import PCODESymEx
from dynamic.execute import DLLExecutor
from pe_utils import PE
from dynamic.implication_graph import extract_constraint_nodes

sys.stdout.reconfigure(line_buffering=True)

# T_α values from bootstrap (our empirical measurements)
KNOWN_ALPHA = {
    'ws2_32':  +0.45,
    'advapi32': -2.04,
    'esent':   -0.36,
    'rpcrt4':  -0.33,
}

def build_incidence_matrix(dll_path, ct_path, max_fns=300, seed=42):
    """Build the function × global binary incidence matrix B."""
    pe = PE(dll_path); ex = DLLExecutor(dll_path)
    rebase = ex.load_base - pe.image_base
    _WRITE = 0x80000000
    gr = [(pe.image_base+s['vrva'], pe.image_base+s['vrva']+s['vsize'])
          for s in pe.sections if s['vsize']>0 and (s['chars']&_WRITE)]
    with open(ct_path) as f:
        fns = [fn for fn in json.load(f)['functions']
               if re.search(r'DAT_[0-9a-fA-F]+', fn.get('pseudocode','') or '')][:max_fns]

    fn_globals = {}  # fn_index → set of canonical global var names
    for i, fn in enumerate(fns):
        va = int(fn['va'],16); sz = fn['size']
        if sz < 4 or sz > 8000: continue
        try:
            code = bytes((ctypes.c_uint8*sz).from_address(va+rebase))
            exe  = PCODESymEx('x86:LE:64:default', code, va, global_ranges=gr)
            r    = exe.run(va, initial_regs={'RSP':0x7FF00000,'RCX':0x1000},
                           max_steps=5000, wall_timeout=6.0)
            nodes = extract_constraint_nodes(fn['name'], r.constraints,
                                             r.silent_guesses, canonicalize=True)
            if nodes:
                global_vars = set()
                for node in nodes:
                    global_vars |= node.global_vars
                if global_vars:
                    fn_globals[i] = global_vars
        except:
            pass

    if not fn_globals:
        return None, None, None

    # Build B matrix
    all_globals = sorted(set(g for gset in fn_globals.values() for g in gset))
    global_idx  = {g: i for i,g in enumerate(all_globals)}
    fn_list     = sorted(fn_globals.keys())

    m = len(fn_list)   # number of functions
    n = len(all_globals)  # number of globals

    B = np.zeros((m, n), dtype=np.float32)
    for row, fn_idx in enumerate(fn_list):
        for g in fn_globals[fn_idx]:
            if g in global_idx:
                B[row, global_idx[g]] = 1.0

    return B, fn_list, all_globals

def marchenko_pastur_pdf(x, gamma, sigma=1.0):
    """Marchenko-Pastur density for eigenvalues of BᵀB/m, ratio γ=n/m."""
    x_minus = sigma**2 * (1 - math.sqrt(gamma))**2
    x_plus  = sigma**2 * (1 + math.sqrt(gamma))**2
    if x <= x_minus or x >= x_plus:
        return 0.0
    return (1.0 / (2 * math.pi * gamma * sigma**2 * x)) * math.sqrt((x_plus - x) * (x - x_minus))

def analyze(dll_path, ct_path, label, max_fns=300):
    print(f'\n{"="*60}')
    print(f'{label}')

    B, fn_list, globals_list = build_incidence_matrix(dll_path, ct_path, max_fns)
    if B is None or B.shape[0] < 5:
        print('  Too few functions'); return None

    m, n = B.shape
    gamma = n / m  # aspect ratio
    print(f'  Matrix B: {m} functions × {n} globals  γ={gamma:.2f}')

    # 1. SVD
    sv = np.linalg.svd(B, compute_uv=False)
    print(f'  Singular values: top5={[f"{s:.2f}" for s in sv[:5]]}')
    print(f'  σ₁={sv[0]:.3f}  σ₂={sv[1]:.3f}  spectral_gap=1-σ₂/σ₁={1-sv[1]/sv[0]:.3f}')

    # 2. Eigenvalues of BᵀB/m (sample covariance) → compare to M-P
    # For large matrices; for small use direct computation
    eigenvalues = (sv ** 2) / m

    # M-P support
    x_minus = (1 - math.sqrt(gamma))**2
    x_plus  = (1 + math.sqrt(gamma))**2
    in_mp   = np.sum((eigenvalues >= x_minus) & (eigenvalues <= x_plus))
    frac_in_mp = in_mp / len(eigenvalues)

    # Wasserstein distance from M-P: compare empirical CDF to M-P CDF
    # Simple proxy: fraction of eigenvalues OUTSIDE M-P bulk
    frac_outside = 1.0 - frac_in_mp

    print(f'  M-P bulk: [{x_minus:.3f}, {x_plus:.3f}]')
    print(f'  Eigenvalues in M-P bulk: {in_mp}/{len(eigenvalues)} = {frac_in_mp:.0%}')
    print(f'  M-P DEVIATION (outside bulk): {frac_outside:.0%}  '
          f'(0%=random, high%=structure)')

    # Largest eigenvalue vs M-P upper bound
    λ_max = eigenvalues[0]
    excess = λ_max / x_plus if x_plus > 0 else 0
    print(f'  λ_max/M-P_upper = {excess:.2f}  (>1 = structure beyond random)')

    # 3. Co-access graph and Fiedler value
    # Co-access: globals as nodes, edge weight = # functions co-accessing both
    co_access = defaultdict(int)
    for fn_idx in fn_list:
        glist = [g for g in (fn_globals_ref.get(fn_idx,[]) if False else [])]

    # Build from B directly
    global_idx_to_name = {i: g for i,g in enumerate(globals_list)}
    fn_to_globals = {}
    for row, fn_idx in enumerate(fn_list):
        accessed = set(np.where(B[row] > 0)[0])
        fn_to_globals[fn_idx] = accessed

    # Co-access edges
    G_coaccess = nx.Graph()
    G_coaccess.add_nodes_from(range(n))
    for row in range(m):
        accessed = list(np.where(B[row] > 0)[0])
        for i in range(len(accessed)):
            for j in range(i+1, len(accessed)):
                u, v = accessed[i], accessed[j]
                if G_coaccess.has_edge(u, v):
                    G_coaccess[u][v]['weight'] += 1
                else:
                    G_coaccess.add_edge(u, v, weight=1)

    # Fiedler value (λ₂ of normalized Laplacian)
    if G_coaccess.number_of_edges() > 0 and G_coaccess.number_of_nodes() > 2:
        try:
            fiedler = nx.algebraic_connectivity(G_coaccess, method='lanczos', tol=1e-5)
        except Exception:
            fiedler = None
    else:
        fiedler = None

    print(f'  Co-access graph: {G_coaccess.number_of_nodes()} nodes, '
          f'{G_coaccess.number_of_edges()} edges')
    print(f'  Fiedler value λ₂: {fiedler:.4f}' if fiedler else '  Fiedler: could not compute')

    # 4. Spectral gap from SVD vs known T_α
    sg = 1.0 - sv[1]/sv[0] if sv[0] > 0 else 0
    known_alpha = KNOWN_ALPHA.get(label.split()[0], None)
    alpha_str = f'{known_alpha:+.2f}' if known_alpha is not None else '?'
    print(f'\n  SUMMARY: spectral_gap={sg:.3f}  '
          f'fiedler={fiedler:.4f if fiedler else 0:.4f}  '
          f'T_α(empirical)={alpha_str}  '
          f'M-P_deviation={frac_outside:.0%}')

    return {
        'label': label,
        'gamma': gamma,
        'spectral_gap_svd': sg,
        'fiedler': fiedler,
        'mp_deviation': frac_outside,
        'lambda_max_ratio': excess,
        'known_alpha': known_alpha,
        'n_fns': m,
        'n_globals': n,
    }


TARGETS = [
    ('TESTS/real_world/windows/ws2_32/ws2_32.dll',
     'TESTS/real_world/windows/ws2_32/calltree.json',   'ws2_32  T_α=+0.45'),
    ('TESTS/real_world/windows/advapi32/advapi32.dll',
     'TESTS/real_world/windows/advapi32/calltree.json', 'advapi32 T_α=-2.04'),
    ('C:/Windows/System32/esent.dll',
     'TESTS/real_world/windows/esent/calltree.json',    'esent    T_α=-0.36'),
    ('TESTS/real_world/windows/rpcrt4/rpcrt4.dll',
     'TESTS/real_world/windows/rpcrt4/calltree.json',   'rpcrt4   T_α=-0.33'),
]

results = []
for dll, ct, lbl in TARGETS:
    try:
        r = analyze(dll, ct, lbl)
        if r: results.append(r)
    except Exception as e:
        print(f'{lbl}: FAILED {e}')

# Test the hypothesis
print(f'\n{"="*65}')
print('HYPOTHESIS TEST: spectral gap / Fiedler value predicts T_α')
print('='*65)
print(f'{"Label":<16} {"sg(SVD)":>8} {"Fiedler":>8} {"M-P dev":>8} {"T_α(emp)":>10}')
print('-'*65)
for r in sorted(results, key=lambda x: -(x['known_alpha'] or 0)):
    fa = f'{r["fiedler"]:.4f}' if r['fiedler'] else 'N/A'
    ta = f'{r["known_alpha"]:+.2f}' if r['known_alpha'] is not None else '?'
    print(f'{r["label"].split()[0]:<16} {r["spectral_gap_svd"]:>8.3f} {fa:>8} '
          f'{r["mp_deviation"]:>7.0%} {ta:>10}')

# Correlation check
sg_vals   = [r['spectral_gap_svd'] for r in results if r['known_alpha'] is not None]
alpha_vals = [r['known_alpha'] for r in results if r['known_alpha'] is not None]
if len(sg_vals) >= 3:
    corr, pval = sp_stats.pearsonr(sg_vals, alpha_vals)
    print(f'\nPearson correlation(spectral_gap, T_α): r={corr:.3f}  p={pval:.3f}')
    if corr < -0.5:
        print('CONFIRMED: larger spectral gap → more negative T_α (faster convergence)')
    elif corr > 0.5:
        print('REVERSED: larger gap → more positive T_α (unexpected)')
    else:
        print('WEAK: spectral gap does not strongly predict T_α (hypothesis partially refuted)')

fv = [r['fiedler'] for r in results if r['fiedler'] and r['known_alpha'] is not None]
av = [r['known_alpha'] for r in results
      if r['fiedler'] and r['known_alpha'] is not None]
if len(fv) >= 3:
    corr_f, pval_f = sp_stats.pearsonr(fv, av)
    print(f'Pearson correlation(Fiedler_λ₂, T_α): r={corr_f:.3f}  p={pval_f:.3f}')

mp_dev = [r['mp_deviation'] for r in results if r['known_alpha'] is not None]
if len(mp_dev) >= 3:
    corr_mp, _ = sp_stats.pearsonr(mp_dev, alpha_vals)
    print(f'Pearson correlation(M-P_deviation, T_α): r={corr_mp:.3f}')
    if abs(corr_mp) > 0.6:
        print('  → M-P deviation IS correlated with convergence rate')

print('\nMathematical interpretation:')
print('  Spectral gap → mixing time of random function sampling')
print('  Fiedler λ₂   → conductance of co-access graph (Cheeger)')
print('  M-P deviation → how far program is from "random" structure')
print('  T_α < -0.5   → Ramanujan-like (super-CLT convergence)')
print('  T_α ≈ -0.5   → CLT regime (independent sampling works)')
print('  T_α > 0      → bimodal/bottlenecked (random sampling diverges)')
