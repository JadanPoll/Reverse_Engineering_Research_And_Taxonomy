"""
spectral_test2.py — Corrected spectral analysis with three fixes:

1. BBP threshold: β_c = √γ (not 1), verified by SymPy
2. Fiedler value: scipy.sparse.linalg.eigsh on normalized Laplacian
3. Brody β: eigenvalue spacing distribution (Poisson→clustering, GOE→expansion)

Plus: corrected B matrix naming (addresses, not BVS canonical names).
"""
import json, ctypes, re, sys, math, time
import numpy as np
from scipy import sparse, stats
from scipy.sparse import csgraph
from scipy.sparse.linalg import eigsh
from scipy.optimize import minimize_scalar
from collections import defaultdict

from dynamic.pcode_sym import PCODESymEx
from dynamic.execute import DLLExecutor
from pe_utils import PE
from dynamic.implication_graph import extract_constraint_nodes

sys.stdout.reconfigure(line_buffering=True)

KNOWN_ALPHA = {
    'ws2_32': +0.45, 'advapi32': -2.04, 'esent': -0.36, 'rpcrt4': -0.33
}

# ── Corrected BBP formula ─────────────────────────────────────────────────────

def bbp_threshold(gamma):
    """BBP threshold β_c = √γ for rectangular spiked covariance model.
    Signal detects when β² > γ, i.e. β > √γ.
    Verified: at β=√γ, λ_spike = (1+√γ)² = λ_max ✓
    Reference: Baik-Ben Arous-Péché 2005, Paul 2007 (Statistica Sinica)
    """
    return math.sqrt(gamma)

def bbp_spike_position(beta, gamma):
    """Spike eigenvalue position when β² > γ (signal detectable).
    λ_spike = (1+β)(1+γ/β)
    """
    if beta**2 <= gamma:
        return (1 + math.sqrt(gamma))**2  # merged in bulk
    return (1 + beta) * (1 + gamma / beta)

def n_bbp_predicted(gamma, snr_per_sample, target_beta=None):
    """Predict N_BBP: observations needed for signal to cross BBP threshold.
    snr_per_sample: signal amplitude per single function observation.
    β(N) = snr_per_sample × √N (CLT growth).
    β_c = √γ → N_BBP = (√γ / snr_per_sample)²
    """
    beta_c = target_beta if target_beta else bbp_threshold(gamma)
    return (beta_c / snr_per_sample) ** 2

# ── Fiedler value via scipy.sparse ───────────────────────────────────────────

def compute_fiedler(adj_matrix_sparse, tol=1e-5):
    """Compute Fiedler value (λ₂) of normalized graph Laplacian.
    Uses scipy.sparse.linalg.eigsh with which='SM' — handles dense 800-node graphs.
    Normalized Laplacian: L = D^(-1/2)(D-A)D^(-1/2), eigenvalues in [0,2].
    Reference: scipy.sparse.csgraph.laplacian(normed=True)
    """
    n = adj_matrix_sparse.shape[0]
    if n < 3:
        return None
    try:
        L = csgraph.laplacian(adj_matrix_sparse, normed=True)
        # eigsh finds smallest eigenvalues; k=3 in case of near-zero numerical issues
        vals, _ = eigsh(L, k=min(4, n-1), which='SM', tol=tol, maxiter=10000)
        vals = np.sort(np.real(vals))
        # λ₁ ≈ 0 (constant eigenvector), λ₂ = Fiedler value
        fiedler = vals[1] if len(vals) > 1 else None
        return fiedler
    except Exception as e:
        return None

# ── Brody β: eigenvalue spacing distribution ─────────────────────────────────

def brody_beta(singular_values, min_spacings=10):
    """Fit Brody parameter β to singular value spacing distribution.
    β ≈ 0 → Poisson spacing (CLUSTERING: eigenvalues clump, modular structure)
    β ≈ 1 → GOE/Wigner-Dyson (EXPANSION: eigenvalue repulsion, good mixing)

    Quick version: use the Kolmogorov-Smirnov distance to Poisson vs GOE.
    Returns β in [0,1], and the repulsion_score (fraction of small gaps).

    Reference: Brody (1973) Lett. Nuovo Cim. 7:482; Wigner surmise.
    """
    sv = np.sort(singular_values)
    if len(sv) < min_spacings + 1:
        return None, None

    # Local unfolding: normalize each spacing by local mean density
    spacings = []
    window = max(3, len(sv) // 20)
    for i in range(1, len(sv)):
        lo = max(0, i - window)
        hi = min(len(sv)-1, i + window)
        local_mean = (sv[hi] - sv[lo]) / (hi - lo) if hi > lo else 1.0
        if local_mean > 1e-10:
            s = (sv[i] - sv[i-1]) / local_mean
            spacings.append(s)

    spacings = np.array(spacings)
    spacings = spacings[spacings > 0]
    if len(spacings) < min_spacings:
        return None, None
    spacings = spacings / np.mean(spacings)

    # Repulsion score: fraction of spacings below ε = 0.1 (mean spacing)
    # Poisson: P(s<ε) ≈ ε       (many clumped pairs → clustering)
    # GOE:     P(s<ε) ≈ π²ε³/6  (strong repulsion → expansion)
    eps = 0.1
    repulsion_score = np.mean(spacings < eps)  # lower = more repulsion = expansion

    # Fit Brody parameter via KS distance
    # Brody CDF: F(s) = 1 - exp(-α·s^(β+1)), α = Γ((β+2)/(β+1))^(β+1)
    from scipy.special import gamma as sp_gamma

    def ks_dist(beta):
        if beta <= 0 or beta >= 1.5:
            return 1.0
        try:
            alpha = sp_gamma((beta + 2) / (beta + 1)) ** (beta + 1)
            brody_cdf = lambda s: 1 - np.exp(-alpha * np.array(s) ** (beta + 1))
            stat, _ = stats.kstest(spacings, brody_cdf)
            return stat
        except:
            return 1.0

    try:
        result = minimize_scalar(ks_dist, bounds=(0.01, 1.2), method='bounded',
                                 options={'xatol': 0.02})
        beta_fit = np.clip(result.x, 0, 1)
    except:
        beta_fit = None

    return beta_fit, repulsion_score

# ── Name → address parser ─────────────────────────────────────────────────────

def name_to_addr(name):
    """Convert canonical BVS name to integer address (the naming fix)."""
    if name.startswith('g_'):
        try: return int(name[2:], 16)
        except: return None
    if name.startswith('f_'):
        # f_BASE_0xOFFSET_... → base address
        parts = name[2:].split('_')
        for p in parts:
            try: return int(p, 16)
            except: continue
    return None

# ── Main analysis ─────────────────────────────────────────────────────────────

def analyze(dll_path, ct_path, label, max_fns=200):
    print(f'\n{"="*62}')
    print(f'{label}  (T_α={KNOWN_ALPHA.get(label, "?")})')

    pe = PE(dll_path); ex = DLLExecutor(dll_path)
    rebase = ex.load_base - pe.image_base
    _WRITE = 0x80000000
    gr = [(pe.image_base+s['vrva'], pe.image_base+s['vrva']+s['vsize'])
          for s in pe.sections if s['vsize']>0 and (s['chars']&_WRITE)]
    with open(ct_path) as f:
        fns = [fn for fn in json.load(f)['functions']
               if re.search(r'DAT_[0-9a-fA-F]+', fn.get('pseudocode','') or '')][:max_fns]

    fn_reads   = {}
    fn_constrs = {}
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
        except: pass

    all_globals = sorted(set(a for s in fn_reads.values() for a in s) |
                         set(a for s in fn_constrs.values() for a in s))
    all_fns     = sorted(set(fn_reads) | set(fn_constrs))
    if len(all_fns) < 5 or len(all_globals) < 5:
        print('  Too few data'); return None

    g_idx = {g: i for i,g in enumerate(all_globals)}
    m, n  = len(all_fns), len(all_globals)
    gamma = n / m

    B = np.zeros((m, n), dtype=np.float32)
    for row, fn in enumerate(all_fns):
        for a in (fn_reads.get(fn, set()) | fn_constrs.get(fn, set())):
            if a in g_idx:
                B[row, g_idx[a]] = 1.0

    print(f'  B: {m} fns × {n} globals  γ={gamma:.2f}')

    # ── SVD ──────────────────────────────────────────────────────────────────
    sv = np.linalg.svd(B, compute_uv=False)
    sg = 1.0 - sv[1]/sv[0] if sv[0] > 0 else 0

    # ── M-P comparison ───────────────────────────────────────────────────────
    eigenvalues = sv**2 / m
    x_min = (1 - math.sqrt(gamma))**2
    x_max = (1 + math.sqrt(gamma))**2
    in_bulk  = np.sum((eigenvalues >= x_min) & (eigenvalues <= x_max))
    mp_dev   = 1.0 - in_bulk / len(eigenvalues)
    lam_ratio = eigenvalues[0] / x_max if x_max > 0 else 0

    # ── Corrected BBP ────────────────────────────────────────────────────────
    beta_c   = bbp_threshold(gamma)
    # Estimate signal SNR from largest outlier eigenvalue
    # λ_spike_obs = eigenvalues[0]; solve for β: (1+β)(1+γ/β) = λ_spike_obs
    if eigenvalues[0] > x_max:
        # Signal is detectable — eigenvalue above M-P bulk
        # Solve (1+β)(1+γ/β) = λ_obs for β
        λ_obs = float(eigenvalues[0])
        # Quadratic: β² - (λ_obs - 1 - γ)β + γ = 0... wait:
        # (1+β)(1+γ/β) = 1 + γ/β + β + γ = λ_obs
        # β + γ/β = λ_obs - 1 - γ  →  β² - (λ_obs-1-γ)β + γ = 0
        a_coef = 1; b_coef = -(λ_obs - 1 - gamma); c_coef = gamma
        disc = b_coef**2 - 4*a_coef*c_coef
        if disc >= 0:
            beta_obs = (-b_coef + math.sqrt(disc)) / 2
            snr_single = beta_obs / math.sqrt(m)
            n_bbp = n_bbp_predicted(gamma, snr_single, beta_c)
        else:
            beta_obs = None; n_bbp = None
    else:
        beta_obs = None; n_bbp = None

    # ── Fiedler value ─────────────────────────────────────────────────────────
    # Build co-access adjacency (globals × globals)
    co = defaultdict(int)
    for row in range(m):
        cols = list(np.where(B[row] > 0)[0])
        for i in range(len(cols)):
            for j in range(i+1, len(cols)):
                co[(cols[i], cols[j])] += 1

    if len(co) > 0:
        rows_arr = [k[0] for k in co]; cols_arr = [k[1] for k in co]
        wts  = list(co.values())
        sym_r = rows_arr + cols_arr; sym_c = cols_arr + rows_arr
        sym_w = wts + wts
        A_sp = sparse.csr_matrix((sym_w, (sym_r, sym_c)), shape=(n, n))
        fiedler = compute_fiedler(A_sp)
    else:
        fiedler = None

    # ── Brody β ──────────────────────────────────────────────────────────────
    brody, repulsion = brody_beta(sv)

    # ── Print results ─────────────────────────────────────────────────────────
    ta = KNOWN_ALPHA.get(label)
    print(f'  spectral_gap={sg:.3f}  M-P_dev={mp_dev:.0%}  λ/upper={lam_ratio:.2f}')
    print(f'  BBP: β_c=√γ={beta_c:.2f}  β_obs={f"{beta_obs:.2f}" if beta_obs else "buried"}  '
          f'N_BBP_pred={f"{n_bbp:.0f}" if n_bbp else "N/A"}')
    print(f'  Fiedler λ₂={f"{fiedler:.4f}" if fiedler else "N/A"}  '
          f'Brody_β={f"{brody:.2f}" if brody else "N/A"}  '
          f'repulsion={f"{1-repulsion:.0%}" if repulsion is not None else "N/A"}')
    print(f'  T_α(emp)={f"{ta:+.2f}" if ta else "?"}  '
          f'prediction: {"SLOW(modular)" if brody and brody < 0.4 else "FAST(expansion)" if brody and brody > 0.7 else "MIXED"}')

    return {
        'label': label, 'gamma': gamma, 'sg': sg, 'mp_dev': mp_dev,
        'lam_ratio': lam_ratio, 'beta_c': beta_c, 'beta_obs': beta_obs,
        'n_bbp': n_bbp, 'fiedler': fiedler, 'brody': brody,
        'repulsion': repulsion, 'alpha': ta,
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

print(f'\n{"="*65}')
print('FULL RESULTS — all three fixes applied')
print(f'{"="*65}')
hdr = f'{"DLL":<12} {"γ":>5} {"sg":>6} {"λ/up":>6} {"β_c":>5} {"Fiedler":>8} {"Brody":>7} {"T_α":>7}'
print(hdr); print('-'*65)
for r in sorted(results, key=lambda x: x['alpha'] or 0):
    ta  = f'{r["alpha"]:+.2f}' if r['alpha'] else '?'
    fi  = f'{r["fiedler"]:.3f}' if r['fiedler'] else 'N/A'
    br  = f'{r["brody"]:.2f}' if r['brody'] else 'N/A'
    bc  = f'{r["beta_c"]:.2f}'
    print(f'{r["label"]:<12} {r["gamma"]:>5.2f} {r["sg"]:>6.3f} '
          f'{r["lam_ratio"]:>6.2f} {bc:>5} {fi:>8} {br:>7} {ta:>7}')

# Correlation tests
from scipy import stats as sp_stats
for key, name in [('sg','spectral_gap'), ('fiedler','Fiedler_λ₂'),
                   ('brody','Brody_β'), ('mp_dev','M-P_deviation')]:
    vals  = [r[key] for r in results if r[key] is not None and r['alpha'] is not None]
    alphas = [r['alpha'] for r in results if r[key] is not None and r['alpha'] is not None]
    if len(vals) >= 3:
        corr, p = sp_stats.pearsonr(vals, alphas)
        marker = '★' if abs(corr) > 0.7 else ' '
        print(f'{marker} corr({name:18s}, T_α) = {corr:+.3f}  p={p:.3f}')

print('\nBrody β interpretation:')
print('  β→0: Poisson spacing (CLUSTERING — eigenvalues clump, modular bottlenecks)')
print('  β→1: GOE spacing    (EXPANSION — eigenvalue repulsion, fast mixing)')
print('  Prediction: higher Brody β → more negative T_α (faster convergence)')
