"""
gf2_survey.py — GF(2) jump density survey across all 22 DLLs.

Tests the hypothesis: n_high_fraction × jump_density_ratio = "sustained information rate"
predicts redundancy cluster (HIGH/MED/LOW) across all DLLs in geometry_data.json.

Confirmed on 4 bootstrapped DLLs:
  advapi32: 0.60 → T_α=-2.04 (fastest)
  esent:    0.15 → T_α=-0.36
  rpcrt4:   0.13 → T_α=-0.33
  ws2_32:   0.085 → T_α=+0.45 (divergent)

Now testing on all 22 DLLs using redundancy cluster as proxy for T_α.
Prediction: higher product → higher redundancy cluster (HIGH > MED > LOW).

Computation: O(N × n²) GF(2) elimination. No bootstrap. No Z3.
Cap at 100 functions, 4s timeout per function → ~3-5 min per DLL.
"""
import json, ctypes, re, sys, time, os, math
import numpy as np
from collections import defaultdict

from dynamic.pcode_sym import PCODESymEx
from dynamic.execute import DLLExecutor
from pe_utils import PE
from dynamic.implication_graph import extract_constraint_nodes

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

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

def gf2_staircase(B_binary):
    """GF(2) rank as each row is added. Returns list of ranks."""
    m, n = B_binary.shape
    pivots = {}
    ranks = []
    rank = 0
    for i in range(m):
        row = B_binary[i].copy()
        for col in sorted(pivots.keys()):
            if row[col]:
                row ^= pivots[col]
        nz = np.where(row)[0]
        if len(nz) > 0:
            rank += 1
            pivots[nz[0]] = row.copy()
        ranks.append(rank)
    return ranks

def make_code_reader(dll_path, pe):
    """Returns a (va, size) -> bytes reader. Works for both DLL and EXE."""
    if dll_path.lower().endswith('.dll'):
        try:
            ex = DLLExecutor(dll_path)
            rebase = ex.load_base - pe.image_base
            def read_dll(va, size):
                return bytes((ctypes.c_uint8*size).from_address(va+rebase))
            return read_dll
        except: pass
    raw = open(dll_path, 'rb').read()
    def read_file(va, size):
        try:
            off = pe.va_to_file_offset(va)
            return raw[off:off+size]
        except: return None
    return read_file

def analyze_gf2(dll_path, ct_path, label, max_fns=100):
    try:
        pe = PE(dll_path)
        reader = make_code_reader(dll_path, pe)
    except Exception as e:
        return None, f'LOAD FAILED: {e}'

    _WRITE = 0x80000000
    gr = [(pe.image_base+s['vrva'], pe.image_base+s['vrva']+s['vsize'])
          for s in pe.sections if s['vsize']>0 and (s['chars']&_WRITE)]

    with open(ct_path, encoding='utf-8') as f:
        all_fns = json.load(f)['functions']
    fns = [fn for fn in all_fns
           if re.search(r'DAT_[0-9a-fA-F]+', fn.get('pseudocode','') or '')][:max_fns]

    fn_reads = {}; fn_constrs = {}
    for fn in fns:
        va = int(fn['va'],16); sz = fn['size']
        if sz < 4 or sz > 8000: continue
        try:
            raw = reader(va, sz)
            if raw is None or len(raw) < sz: continue
            exe = PCODESymEx('x86:LE:64:default', raw, va,
                             global_ranges=gr, verbose=False)
            r   = exe.run(va, initial_regs={'RSP':0x7FF00000,'RCX':0x1000},
                          max_steps=4000, wall_timeout=4.0)
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
    all_fns_list = sorted(set(fn_reads) | set(fn_constrs))
    if len(all_fns_list) < 10 or len(all_globals) < 5:
        return None, f'too few ({len(all_fns_list)} fns, {len(all_globals)} globals)'

    g_idx = {g: i for i,g in enumerate(all_globals)}
    m, n  = len(all_fns_list), len(all_globals)

    B = np.zeros((m, n), dtype=np.uint8)
    for row, fn in enumerate(all_fns_list):
        for a in (fn_reads.get(fn,set()) | fn_constrs.get(fn,set())):
            if a in g_idx: B[row, g_idx[a]] = 1

    # GF(2) staircase
    ranks = gf2_staircase(B)
    final_rank = ranks[-1]

    # Leverage n_high (fraction with ℓ > 0.5, using top-k SVD)
    try:
        U, S, _ = np.linalg.svd(B.astype(float), full_matrices=False)
        k = max(1, int(np.sum(S > 0.5)))
        leverage = np.sum(U[:,:k]**2, axis=1)
        n_high = int(np.sum(leverage > 0.5))
        n_high_frac = n_high / m
    except:
        n_high_frac = 0.0

    # Jump density ratio (late/early thirds)
    third = max(1, m // 3)
    jumps = [1 if ranks[i] > ranks[i-1] else 0 for i in range(1, m)]
    density_early = sum(jumps[:third]) / third
    density_late  = sum(jumps[max(0,m-1-third):]) / third
    ratio = density_late / density_early if density_early > 0 else 0.0

    # The product: sustained information rate
    product = n_high_frac * ratio

    return {
        'label': label, 'm': m, 'n': n,
        'gf2_rank': final_rank,
        'gf2_redundancy': 1 - final_rank/m,
        'n_high_frac': n_high_frac,
        'density_early': density_early,
        'density_late': density_late,
        'ratio': ratio,
        'product': product,
    }, None

# ── Discover all DLL targets ──────────────────────────────────────────────────
SKIP = {'combase', 'kernelbase', 'ntdll', 'python312', 'lib_openssl'}

WIN_DIR = 'TESTS/real_world/windows'
EMU_DIR = 'TESTS/real_world/emulators'
LIB_DIR = 'TESTS/real_world'

targets = []
for base in (WIN_DIR, EMU_DIR):
    if not os.path.isdir(base): continue
    for d in sorted(os.listdir(base)):
        if d in SKIP: continue
        ct = f'{base}/{d}/calltree.json'
        if not os.path.exists(ct): continue
        dll = next((f'{base}/{d}/{f}' for f in os.listdir(f'{base}/{d}')
                    if f.endswith(('.dll','.exe'))), None)
        if dll: targets.append((dll, ct, d))

for d in sorted(os.listdir(LIB_DIR)):
    subdir = f'{LIB_DIR}/{d}'
    if not os.path.isdir(subdir): continue
    if d in SKIP: continue
    ct = f'{subdir}/calltree.json'
    if not os.path.exists(ct): continue
    dll = next((f'{subdir}/{f}' for f in os.listdir(subdir)
                if f.endswith('.dll')), None)
    if dll: targets.append((dll, ct, f'lib_{d}'))

# Also add schannel, ffmpeg, etc. from geometry_data.json
EXTRA = [
    ('C:/Windows/System32/schannel.dll',
     'TESTS/real_world/windows/schannel/calltree.json', 'schannel'),
    ('C:/Users/nathan37/Desktop/ffmpeg_build/ffmpeg-master-latest-win64-gpl-shared/bin/swresample-6.dll',
     'TESTS/real_world/ffmpeg/swresample/calltree.json', 'ffmpeg_swresample'),
    ('C:/Users/nathan37/Desktop/ffmpeg_build/ffmpeg-master-latest-win64-gpl-shared/bin/avutil-60.dll',
     'TESTS/real_world/ffmpeg/avutil/calltree.json', 'ffmpeg_avutil'),
]
for dll, ct, lbl in EXTRA:
    if os.path.exists(ct) and os.path.exists(dll):
        targets.append((dll, ct, lbl))

print(f'Found {len(targets)} targets')

# ── Known values for validation ───────────────────────────────────────────────
KNOWN_ALPHA = {'ws2_32':+0.45,'advapi32':-2.04,'esent':-0.36,'rpcrt4':-0.33}

# Load geometry_data.json for redundancy clusters
redundancy_map = {}
if os.path.exists('geometry_data.json'):
    with open('geometry_data.json') as f:
        for r in json.load(f):
            redundancy_map[r['label']] = r.get('redundancy', None)

# ── Run analysis ──────────────────────────────────────────────────────────────
results = []
for dll, ct, lbl in targets:
    t0 = time.perf_counter()
    print(f'  {lbl}...', file=sys.stderr, flush=True)
    r, err = analyze_gf2(dll, ct, lbl, max_fns=100)
    elapsed = time.perf_counter() - t0
    if r:
        r['elapsed'] = elapsed
        r['known_alpha'] = KNOWN_ALPHA.get(lbl)
        r['known_redundancy'] = redundancy_map.get(lbl)
        cluster = ('HIGH' if (r['known_redundancy'] or 0) > 0.10 else
                   'MED'  if (r['known_redundancy'] or 0) > 0.02 else
                   'LOW'  if r['known_redundancy'] is not None else '?')
        r['cluster'] = cluster
        results.append(r)
        print(f'  {lbl}: product={r["product"]:.3f} '
              f'n_high={r["n_high_frac"]:.2f} ratio={r["ratio"]:.2f} '
              f'cluster={cluster} ({elapsed:.0f}s)', flush=True)
    else:
        print(f'  {lbl}: SKIP — {err}', flush=True)

# ── Results table ─────────────────────────────────────────────────────────────
print(f'\n{"="*75}')
print('GF(2) SUSTAINED INFORMATION RATE — all DLLs')
print('Hypothesis: product = n_high_frac × ratio predicts redundancy cluster')
print(f'{"="*75}')
print(f'{"Label":<22} {"product":>8} {"n_high":>7} {"ratio":>7} {"Cluster":>8} {"T_α":>7}')
print('-'*65)

for r in sorted(results, key=lambda x: -x['product']):
    ta = f'{r["known_alpha"]:+.2f}' if r['known_alpha'] else '?'
    print(f'{r["label"]:<22} {r["product"]:>8.3f} {r["n_high_frac"]:>7.2f} '
          f'{r["ratio"]:>7.2f} {r["cluster"]:>8} {ta:>7}')

# ── Statistical test ──────────────────────────────────────────────────────────
from scipy import stats as sp_stats
print(f'\nCLUSTER ANALYSIS:')
for cluster in ['HIGH','MED','LOW']:
    cluster_products = [r['product'] for r in results if r['cluster'] == cluster]
    if cluster_products:
        print(f'  {cluster}: n={len(cluster_products)}  '
              f'mean_product={np.mean(cluster_products):.3f}  '
              f'[{min(cluster_products):.3f}, {max(cluster_products):.3f}]')

# T_α correlation (4 DLLs)
alpha_results = [r for r in results if r['known_alpha'] is not None]
if len(alpha_results) >= 3:
    products = [r['product'] for r in alpha_results]
    alphas   = [r['known_alpha'] for r in alpha_results]
    corr, p  = sp_stats.pearsonr(products, alphas)
    print(f'\nCorr(product, T_α) on {len(alpha_results)} bootstrapped DLLs: r={corr:.3f} p={p:.3f}')
    if abs(corr) > 0.9: print('  ★ STRONG: product predicts T_α')
    elif abs(corr) > 0.7: print('  ~ MODERATE: product partially predicts T_α')
    else: print('  ✗ WEAK: product does not predict T_α')

# Kruskal-Wallis test across clusters
cluster_groups = {}
for r in results:
    c = r['cluster']
    if c != '?':
        cluster_groups.setdefault(c, []).append(r['product'])

if len(cluster_groups) >= 2:
    groups = [v for k,v in sorted(cluster_groups.items()) if len(v) >= 2]
    if len(groups) >= 2:
        stat, p_kw = sp_stats.kruskal(*groups)
        print(f'Kruskal-Wallis test (product differs by cluster): H={stat:.2f} p={p_kw:.3f}')
        if p_kw < 0.05: print('  ★ SIGNIFICANT: product distinguishes clusters')
        else: print('  ✗ NOT significant')

print('\nNEW DISCRIMINANT: sustained_information_rate = n_high_frac × jump_density_ratio')
print('Computable from B matrix in O(N×n²), no bootstrap, no Z3.')
print('Higher = expander-like (advapi32), Lower = saturating/bimodal (ws2_32)')
