"""
talpha_survey.py — Bootstrap T_α for all loadable DLLs overnight.

Extends redundancy_convergence.py to run on all DLLs in geometry_data.json.
Saves results incrementally to talpha_results.json so nothing is lost if interrupted.
Run once, come back to full T_α data for all DLLs.

T_α = slope of log(std) vs log(N) for redundancy estimator.
  T_α << -0.5: super-CLT convergence (advapi32-like)
  T_α ≈ -0.5: CLT regime
  T_α > 0:    divergent (ws2_32-like)

Product = n_high_frac × jump_density_ratio predicts T_α (confirmed on 4 DLLs, r=-0.967).
This survey tests whether that holds across 15+ DLLs.
"""
import json, ctypes, re, sys, os, time, math, random
import numpy as np
from collections import defaultdict
from scipy import stats as sp_stats

from dynamic.pcode_sym import PCODESymEx
from dynamic.execute import DLLExecutor
from pe_utils import PE
from dynamic.implication_graph import extract_constraint_nodes, build_implication_graph

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

SAMPLE_SIZES = [10, 25, 50, 100, 200]
TOTAL_BUDGET = 300   # total function observations (less than full 500 for speed)

def n_reps(n): return max(2, min(30, TOTAL_BUDGET // n))

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

def make_reader(dll_path, pe):
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

def collect_fn_nodes(dll_path, ct_path, max_fns=300, seed=42):
    """Pre-collect constraint nodes from up to max_fns functions. Returns fn_nodes dict."""
    pe = PE(dll_path)
    reader = make_reader(dll_path, pe)
    _WRITE = 0x80000000
    gr = [(pe.image_base+s['vrva'], pe.image_base+s['vrva']+s['vsize'])
          for s in pe.sections if s['vsize']>0 and (s['chars']&_WRITE)]
    with open(ct_path, encoding='utf-8') as f:
        fns = [fn for fn in json.load(f)['functions']
               if re.search(r'DAT_[0-9a-fA-F]+', fn.get('pseudocode','') or '')][:max_fns]

    fn_nodes = {}
    for i, fn in enumerate(fns):
        va = int(fn['va'],16); sz = fn['size']
        if sz < 4 or sz > 8000: continue
        if i % 100 == 0:
            print(f'    collecting {i}/{len(fns)}...', file=sys.stderr, flush=True)
        try:
            raw = reader(va, sz)
            if raw is None or len(raw) < sz: continue
            exe = PCODESymEx('x86:LE:64:default', raw, va,
                             global_ranges=gr, verbose=False)
            r   = exe.run(va, initial_regs={'RSP':0x7FF00000,'RCX':0x1000},
                          max_steps=4000, wall_timeout=5.0)
            nodes = extract_constraint_nodes(fn['name'], r.constraints,
                                             r.silent_guesses, canonicalize=True)
            if nodes:
                nodes_tagged = []
                for node in nodes:
                    node.collection_order = i
                    nodes_tagged.append(node)
                fn_nodes[i] = nodes_tagged
        except: pass
    return fn_nodes

def bootstrap_talpha(fn_nodes, max_pairs=600, seed=42):
    """Bootstrap T_α from pre-collected fn_nodes. Returns alpha, cv_at_max_n, curve."""
    rng = random.Random(seed)
    valid_indices = sorted(fn_nodes.keys())
    if len(valid_indices) < 20:
        return None, None, None

    curve = {}
    for n in SAMPLE_SIZES:
        if n > len(valid_indices): continue
        reps = n_reps(n)
        sample_reds = []
        for _ in range(reps):
            sampled = rng.sample(valid_indices, n)
            subset = [node for idx in sampled for node in fn_nodes[idx]]
            if len(subset) < 3: continue
            impl = build_implication_graph(subset, max_pairs=max_pairs,
                                           timeout_per_ms=1500, verbose=False)
            sample_reds.append(impl.redundancy)
        if len(sample_reds) >= 2:
            mean_r = np.mean(sample_reds)
            std_r  = np.std(sample_reds)
            cv     = std_r / mean_r if mean_r > 0 else 0
            curve[n] = {'mean': mean_r, 'std': std_r, 'cv': cv, 'reps': reps}

    if len(curve) < 3:
        return None, None, curve

    # Fit T_α: log(std) = T_α × log(N) + const
    ns   = sorted(curve.keys())
    stds = [curve[n]['std'] for n in ns]
    valid = [(n, s) for n, s in zip(ns, stds) if s > 1e-8]
    if len(valid) < 3:
        return None, None, curve

    log_n = [math.log(n) for n,_ in valid]
    log_s = [math.log(s) for _,s in valid]
    slope, _, _, _, _ = sp_stats.linregress(log_n, log_s)

    cv_max = curve.get(max(ns), {}).get('cv', None)
    return slope, cv_max, curve


# ── Target discovery ──────────────────────────────────────────────────────────
SKIP = {'python312', 'combase', 'kernelbase', 'ntdll', 'lib_openssl'}
TOO_SMALL = {'lib_miniz', 'lib_zlib', 'lib_mbedtls', 'lib_lua', 'cabinet',
             'lib_bcrypt', 'lib_sqlite', 'py_sqlite', 'py_libcrypto'}  # < 50 fns

WIN_DIR = 'TESTS/real_world/windows'
EMU_DIR = 'TESTS/real_world/emulators'
LIB_DIR = 'TESTS/real_world'
EXTRA   = [
    ('C:/Windows/System32/schannel.dll',
     'TESTS/real_world/windows/schannel/calltree.json', 'schannel'),
    ('C:/Users/nathan37/Desktop/ffmpeg_build/ffmpeg-master-latest-win64-gpl-shared/bin/swresample-6.dll',
     'TESTS/real_world/ffmpeg/swresample/calltree.json', 'ffmpeg_swresample'),
    ('C:/Windows/System32/esent.dll',
     'TESTS/real_world/windows/esent/calltree.json', 'esent'),
]

targets = []
for base in (WIN_DIR, EMU_DIR):
    if not os.path.isdir(base): continue
    for d in sorted(os.listdir(base)):
        if d in SKIP or d in TOO_SMALL: continue
        ct = f'{base}/{d}/calltree.json'
        if not os.path.exists(ct): continue
        dll = next((f'{base}/{d}/{f}' for f in os.listdir(f'{base}/{d}')
                    if f.endswith(('.dll','.exe'))), None)
        if dll: targets.append((dll, ct, d))

for dll, ct, lbl in EXTRA:
    if os.path.exists(ct) and os.path.exists(dll) and lbl not in [t[2] for t in targets]:
        targets.append((dll, ct, lbl))

print(f'Survey targets: {len(targets)}')
for _, _, lbl in targets:
    print(f'  {lbl}')
print()

# ── Load existing results ─────────────────────────────────────────────────────
RESULTS_FILE = 'talpha_results.json'
existing = {}
if os.path.exists(RESULTS_FILE):
    with open(RESULTS_FILE) as f:
        for r in json.load(f):
            existing[r['label']] = r
    print(f'Loaded {len(existing)} existing results from {RESULTS_FILE}')

# ── Run survey ────────────────────────────────────────────────────────────────
all_results = list(existing.values())

for dll, ct, label in targets:
    if label in existing:
        print(f'  {label}: already done (T_α={existing[label].get("talpha","?")})')
        continue

    t0 = time.perf_counter()
    print(f'\n{"="*55}')
    print(f'  {label}')

    try:
        fn_nodes = collect_fn_nodes(dll, ct, max_fns=300)
        n_fns = len(fn_nodes)
        total_nodes = sum(len(v) for v in fn_nodes.values())
        print(f'  Collected: {n_fns} fns, {total_nodes} constraint nodes')

        if n_fns < 20:
            print(f'  SKIP: too few functions ({n_fns})')
            continue

        alpha, cv_max, curve = bootstrap_talpha(fn_nodes)
        elapsed = time.perf_counter() - t0

        if alpha is None:
            print(f'  SKIP: insufficient curve data ({elapsed:.0f}s)')
            continue

        result = {
            'label': label,
            'talpha': round(alpha, 3),
            'cv_at_max_n': round(cv_max, 3) if cv_max else None,
            'n_fns_collected': n_fns,
            'n_nodes': total_nodes,
            'elapsed_s': round(elapsed, 0),
            'curve': {str(k): {kk: round(vv, 4) for kk, vv in v.items()}
                      for k, v in (curve or {}).items()},
        }

        print(f'  T_α = {alpha:+.3f}  cv_at_max_n = {cv_max:.2f}  ({elapsed:.0f}s)')
        if alpha < -1.0:
            print(f'  → SUPER-CLT convergence (Ramanujan-like expander)')
        elif alpha < -0.4:
            print(f'  → CLT regime (normal convergence)')
        elif alpha < 0:
            print(f'  → SUB-CLT (correlated sampling, slower than expected)')
        else:
            print(f'  → DIVERGENT (bimodal, stable law)')

        all_results.append(result)
        # Save incrementally
        with open(RESULTS_FILE, 'w') as f:
            json.dump(all_results, f, indent=2)

    except Exception as e:
        print(f'  FAILED: {e}')
        elapsed = time.perf_counter() - t0
        print(f'  ({elapsed:.0f}s)')

# ── Final summary ──────────────────────────────────────────────────────────────
print(f'\n{"="*65}')
print(f'T_α SURVEY COMPLETE — {len(all_results)} DLLs')
print(f'{"="*65}')
print(f'{"Label":<22} {"T_α":>8} {"cv_max":>8} {"n_fns":>7}')
print('-'*50)
for r in sorted(all_results, key=lambda x: x.get('talpha', 0)):
    ta = r.get('talpha', '?')
    cv = r.get('cv_at_max_n', '?')
    nf = r.get('n_fns_collected', '?')
    ta_str = f'{ta:+.3f}' if isinstance(ta, float) else str(ta)
    cv_str = f'{cv:.2f}' if isinstance(cv, float) else str(cv)
    print(f'{r["label"]:<22} {ta_str:>8} {cv_str:>8} {nf:>7}')

# Correlation with geometry_data product
if os.path.exists('geometry_data.json') and os.path.exists('talpha_results.json'):
    with open('geometry_data.json') as f:
        geo = {r['label']: r for r in json.load(f)}

    paired = []
    for r in all_results:
        g = geo.get(r['label'], {})
        # We need product from gf2_survey — it's not in geometry_data
        # But redundancy IS there
        red = g.get('redundancy')
        ta  = r.get('talpha')
        if red is not None and ta is not None:
            paired.append((red, ta, r['label']))

    if len(paired) >= 5:
        reds = [p[0] for p in paired]
        tas  = [p[1] for p in paired]
        corr, p_val = sp_stats.pearsonr(reds, tas)
        print(f'\ncorr(redundancy, T_α) across {len(paired)} DLLs: r={corr:.3f} p={p_val:.3f}')
        print('(If r significant: redundancy and T_α are NOT orthogonal — update theory)')

print(f'\nResults saved to {RESULTS_FILE}')
print('Load with: json.load(open("talpha_results.json"))')
