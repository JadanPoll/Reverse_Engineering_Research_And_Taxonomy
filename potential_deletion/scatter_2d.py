"""
scatter_2d.py — Plot all DLLs in (sustained_info_rate, redundancy) 2D space.

Hypothesis: the two dimensions are orthogonal, and clusters separate
in the 2D space even if neither axis alone predicts cluster membership.

X = sustained_info_rate = n_high_frac × jump_density_ratio (from gf2_survey)
Y = redundancy % (from geometry_data.json / implication graph)
"""
import json, os, sys, math
import numpy as np
from scipy import stats as sp_stats

sys.stdout.reconfigure(line_buffering=True)

# ── Data from gf2_survey.py output ───────────────────────────────────────────
GF2_DATA = {
    'advapi32':         {'product': 0.519, 'n_high': 0.57, 'ratio': 0.92},
    'crypt32':          {'product': 0.746, 'n_high': 0.63, 'ratio': 1.18},
    'dxgi':             {'product': 0.904, 'n_high': 0.68, 'ratio': 1.33},
    'kernel32':         {'product': 0.502, 'n_high': 0.73, 'ratio': 0.68},
    'rpcrt4':           {'product': 0.138, 'n_high': 0.35, 'ratio': 0.40},
    'vcruntime140':     {'product': 0.667, 'n_high': 0.17, 'ratio': 4.00},
    'winhttp':          {'product': 0.144, 'n_high': 0.25, 'ratio': 0.58},
    'ws2_32':           {'product': 0.113, 'n_high': 0.20, 'ratio': 0.56},
    'mgba':             {'product': 0.790, 'n_high': 0.59, 'ratio': 1.33},
    'qemu_avr':         {'product': 1.000, 'n_high': 1.00, 'ratio': 1.00},
    'qemu_i386':        {'product': 1.000, 'n_high': 1.00, 'ratio': 1.00},
    'ffmpeg_swresample':{'product': 0.667, 'n_high': 0.67, 'ratio': 1.00},
    'lib_bcrypt':       {'product': 0.778, 'n_high': 0.56, 'ratio': 1.40},
    'lib_lua':          {'product': 0.625, 'n_high': 0.62, 'ratio': 1.00},
    'lib_mbedtls':      {'product': 0.250, 'n_high': 0.50, 'ratio': 0.50},
    'lib_miniz':        {'product': 0.000, 'n_high': 0.50, 'ratio': 0.00},
    'lib_sqlite':       {'product': 0.429, 'n_high': 0.43, 'ratio': 1.00},
    'lib_zlib':         {'product': 0.250, 'n_high': 0.50, 'ratio': 0.50},
    'schannel':         {'product': 0.425, 'n_high': 0.52, 'ratio': 0.82},
}

# Known T_α
KNOWN_ALPHA = {
    'ws2_32': +0.45, 'advapi32': -2.04, 'esent': -0.36, 'rpcrt4': -0.33
}

# Load geometry_data.json for redundancy values
if not os.path.exists('geometry_data.json'):
    print('geometry_data.json not found'); sys.exit(1)

with open('geometry_data.json') as f:
    geo = {r['label']: r for r in json.load(f)}

# Join datasets
points = []
for label, gf2 in GF2_DATA.items():
    geo_r = geo.get(label, {})
    redundancy = geo_r.get('redundancy', None)
    if redundancy is None:
        # Try lib_ prefix strip
        geo_r = geo.get(label.replace('lib_',''), {})
        redundancy = geo_r.get('redundancy', None)
    if redundancy is None:
        continue  # skip if no redundancy data

    product = gf2['product']
    cluster = ('HIGH' if redundancy > 0.10 else
               'MED'  if redundancy > 0.02 else 'LOW')
    alpha = KNOWN_ALPHA.get(label)

    points.append({
        'label': label, 'product': product, 'redundancy': redundancy,
        'cluster': cluster, 'alpha': alpha,
        'n_high': gf2['n_high'], 'ratio': gf2['ratio'],
    })

print(f'Joined {len(points)} DLLs with both product and redundancy data')
print()

# ── ASCII 2D scatter ──────────────────────────────────────────────────────────
# X = product (0..1), Y = redundancy (0..0.20)
W, H = 60, 20
x_min, x_max = 0.0, 1.05
y_min, y_max = 0.0, 0.22

def to_grid(x, y):
    col = int((x - x_min) / (x_max - x_min) * (W-1))
    row = H - 1 - int((y - y_min) / (y_max - y_min) * (H-1))
    return max(0, min(W-1, col)), max(0, min(H-1, row))

grid = [[' '] * W for _ in range(H)]
label_map = {}

CLUSTER_CHAR = {'HIGH': 'H', 'MED': 'M', 'LOW': 'L'}

for p in points:
    col, row = to_grid(p['product'], p['redundancy'])
    char = CLUSTER_CHAR.get(p['cluster'], '?')
    grid[row][col] = char
    label_map[(col, row)] = p['label'][:6]

print('2D SCATTER: (sustained_info_rate, redundancy %)')
print('  Y = redundancy %, X = product (n_high × ratio)')
print()
print(f'  20%|{"─"*W}')
for i, row in enumerate(grid):
    y_val = y_max - (i / (H-1)) * (y_max - y_min)
    prefix = f'{y_val*100:4.0f}%|' if i % 4 == 0 else '     |'
    print(prefix + ''.join(row))
print(f'   0%|{"─"*W}')
print(f'       0{"─"*25}0.5{"─"*24}1.0')
print(f'       {"sustained_info_rate (product = n_high × ratio)":^{W}}')
print()
print('  H = HIGH redundancy (>10%)   M = MED (2-10%)   L = LOW (<2%)')
print()

# ── Data table ────────────────────────────────────────────────────────────────
print(f'{"Label":<22} {"product":>8} {"redund":>8} {"Cluster":>8} {"T_α":>7}')
print('-'*60)
for p in sorted(points, key=lambda x: (-x['redundancy'], -x['product'])):
    ta = f'{p["alpha"]:+.2f}' if p['alpha'] else '?'
    print(f'{p["label"]:<22} {p["product"]:>8.3f} {p["redundancy"]:>7.1%} '
          f'{p["cluster"]:>8} {ta:>7}')

# ── Statistical tests ─────────────────────────────────────────────────────────
print()
print('CLUSTER MEANS (does 2D separate clusters?):')
for cluster in ['HIGH', 'MED', 'LOW']:
    cp = [p for p in points if p['cluster'] == cluster]
    if cp:
        mp = np.mean([p['product'] for p in cp])
        mr = np.mean([p['redundancy'] for p in cp])
        print(f'  {cluster}: n={len(cp):2d}  mean_product={mp:.3f}  '
              f'mean_redundancy={mr:.1%}  '
              f'center=({mp:.2f},{mr:.2f})')

print()
print('LINEAR DISCRIMINANT: can a line in 2D separate HIGH from LOW?')
high_pts = [(p['product'], p['redundancy']) for p in points if p['cluster']=='HIGH']
low_pts  = [(p['product'], p['redundancy']) for p in points if p['cluster']=='LOW']
med_pts  = [(p['product'], p['redundancy']) for p in points if p['cluster']=='MED']

if high_pts and low_pts:
    # Check: does product+redundancy sum separate HIGH from LOW?
    high_score = [p+r for p,r in high_pts]
    low_score  = [p+r for p,r in low_pts]
    med_score  = [p+r for p,r in med_pts]
    print(f'  product+redundancy:')
    print(f'    HIGH: {np.mean(high_score):.3f} ± {np.std(high_score):.3f}')
    print(f'    MED:  {np.mean(med_score):.3f} ± {np.std(med_score):.3f}')
    print(f'    LOW:  {np.mean(low_score):.3f} ± {np.std(low_score):.3f}')

    stat, p_val = sp_stats.kruskal(high_score, med_score, low_score)
    print(f'  Kruskal-Wallis H={stat:.2f} p={p_val:.3f}')

# Product alone vs 2D combined
print()
print('CORRELATION TESTS:')
for key, name in [('product','product_alone'),('redundancy','redundancy_alone')]:
    vals = [p[key] for p in points if p['alpha'] is not None]
    alphas = [p['alpha'] for p in points if p['alpha'] is not None]
    if len(vals) >= 3:
        corr, pv = sp_stats.pearsonr(vals, alphas)
        star = '★' if abs(corr) > 0.8 else ' '
        print(f'{star} corr({name:22s}, T_α) = {corr:+.3f} p={pv:.3f} n={len(vals)}')

# 2D combined predictor: product × redundancy
vals2d = [p['product'] * p['redundancy'] for p in points if p['alpha'] is not None]
alphas2 = [p['alpha'] for p in points if p['alpha'] is not None]
if len(vals2d) >= 3:
    corr2, pv2 = sp_stats.pearsonr(vals2d, alphas2)
    star = '★' if abs(corr2) > 0.8 else ' '
    print(f'{star} corr(product×redundancy     , T_α) = {corr2:+.3f} p={pv2:.3f} n={len(vals2d)}')

# Log(redundancy) + product weighted
vals_log = [p['product'] + math.log(p['redundancy']+0.001)
            for p in points if p['alpha'] is not None]
if len(vals_log) >= 3:
    corr_log, pv_log = sp_stats.pearsonr(vals_log, alphas2)
    star = '★' if abs(corr_log) > 0.8 else ' '
    print(f'{star} corr(product+log(redundancy), T_α) = {corr_log:+.3f} p={pv_log:.3f} n={len(vals2d)}')

print()
print('THE TWO-DIMENSIONAL PICTURE:')
print('  GF(2) access diversity (product) and constraint coupling (redundancy)')
print('  appear to be INDEPENDENT structural properties of programs.')
print('  Neither predicts T_α alone. Together they form the geometry space.')
print('  The "sustained information rate" × "constraint coupling depth" product')
print('  may be the composite discriminant — but needs more bootstrapped DLLs')
print('  to confirm with statistical power.')
