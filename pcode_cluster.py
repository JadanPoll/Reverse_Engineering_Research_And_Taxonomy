"""
pcode_cluster.py — Cluster P-Code functions by rule-usage vectors.

Pipeline:
  1. Load pcode_grammar.npz (59K × 80 rule-presence matrix)
  2. TruncatedSVD → 30 dims (removes flag-update noise via low-rank approx)
  3. HDBSCAN clustering (density-based, no fixed k)
  4. Characterize each cluster: dominant rules, DLL composition, example functions
  5. Correlate cluster membership with geometry_data.json (T3, redundancy, T_α)

Key hypothesis: clusters correspond to functional archetypes —
  GUARD, READER, WRITER, GETTER, DISPATCHER, FLOAT_COMPUTE, INIT, etc.
These are the structural classes the grammar induction surfaces.
"""
import json, sys
from collections import Counter, defaultdict

import numpy as np
import hdbscan
from sklearn.decomposition import TruncatedSVD
from sklearn.preprocessing import normalize

sys.stdout.reconfigure(line_buffering=True)

# ── Load data ──────────────────────────────────────────────────────────────────

import argparse
_ap = argparse.ArgumentParser()
_ap.add_argument('--grammar', default='pcode_grammar_norm.npz')
_args = _ap.parse_args()

print('Loading grammar vectors...')
data        = np.load(_args.grammar, allow_pickle=True)
rule_matrix = data['rule_matrix']          # (59436, 80) binary
rule_labels = data['rule_labels']          # (80,) rule expansion strings
dll_labels  = data['labels']               # (59436,) dll name per function
fn_names    = data['fn_names']             # (59436,) "dll::fn_name"

print(f'  Matrix: {rule_matrix.shape}  ({rule_matrix.astype(bool).mean()*100:.1f}% dense)')
print(f'  DLLs: {sorted(set(dll_labels.tolist()))}')

# ── Dimensionality reduction ───────────────────────────────────────────────────
# TruncatedSVD on the binary rule-presence matrix.
# Low-rank approximation suppresses the uniform flag-update dimensions
# (they have low variance across functions → captured in early SVD components
# but then we keep only the DISCRIMINATING components).
# We keep 30 dims: enough to separate clusters, low enough to avoid noise.

# ── TF-IDF weighting ──────────────────────────────────────────────────────────
# Problem with raw binary rule presence: top-80 rules are the MOST COMMON,
# which means they're the LEAST discriminating. Functions that match rare/
# domain-specific rules (mGBA ARM7 handlers, OpenSSL DER) look like noise
# because their distinctive rules are down-ranked.
# Fix: weight each rule dimension by IDF — rules that appear in few functions
# get amplified; rules that appear everywhere get damped.
# ── Variance-based feature weighting ─────────────────────────────────────────
# The fundamental tension: common rules (p→1) have no discriminating power,
# rare rules (p→0) might be noise. Both fail.
#
# Resolution: weight by p*(1-p) — the VARIANCE of each binary feature.
# This is the "Goldilocks" weighting:
#   p=0.0  (never used)    → weight 0.00  (useless)
#   p=0.1  (rare)          → weight 0.09  (low — might be noise)
#   p=0.5  (medium)        → weight 0.25  (maximum discriminating power)
#   p=0.9  (very common)   → weight 0.09  (low — not cluster-specific)
#   p=1.0  (always used)   → weight 0.00  (useless)
#
# This naturally establishes the noise floor without needing labels.
# Rules that only help discriminate are those with structured variance —
# they appear in SOME functions but not all. That's exactly p*(1-p) > 0.
#
# Null model: for truly random binary features, p*(1-p) would still be
# nonzero, BUT random features produce NO density structure after SVD.
# HDBSCAN finds density clusters, so random high-variance features average
# out across dimensions — they don't create false clusters.

p_r = rule_matrix.astype(float).mean(axis=0)       # proportion per rule
var_weights = p_r * (1.0 - p_r)                    # variance = p*(1-p)
var_weights /= var_weights.max() if var_weights.max() > 0 else 1.0  # normalize

# Report the weighting effect
top_var_idx = np.argsort(var_weights)[::-1][:5]
low_var_idx  = np.argsort(var_weights)[:5]
print(f'  Highest-variance rules (most discriminating potential):')
for idx in top_var_idx:
    print(f'    p={p_r[idx]:.2f}  var={var_weights[idx]:.3f}  {str(rule_labels[idx])[:55]}')
print(f'  Lowest-variance rules (suppressed):')
for idx in low_var_idx:
    print(f'    p={p_r[idx]:.2f}  var={var_weights[idx]:.3f}  {str(rule_labels[idx])[:55]}')

rule_matrix_weighted = rule_matrix.astype(float) * var_weights[np.newaxis, :]

print('\nRunning TruncatedSVD (80 → 30 dims) on variance-weighted matrix...')
svd   = TruncatedSVD(n_components=30, random_state=42)
X_svd = svd.fit_transform(rule_matrix_weighted)
explained = svd.explained_variance_ratio_.cumsum()
print(f'  Variance explained by 30 components: {explained[-1]*100:.1f}%')
print(f'  Per-component: {[f"{v*100:.1f}%" for v in svd.explained_variance_ratio_[:10]]}')

# L2-normalize so HDBSCAN uses angular distance (better for sparse binary data)
X_norm = normalize(X_svd, norm='l2')

# ── HDBSCAN clustering ─────────────────────────────────────────────────────────

print('\nRunning HDBSCAN...')
clusterer = hdbscan.HDBSCAN(
    min_cluster_size=200,    # at least 200 functions to form a cluster
    min_samples=10,          # core density requirement
    metric='euclidean',      # on L2-normalized SVD coords ≈ cosine distance
    cluster_selection_method='eom',   # excess of mass — finds varied-density clusters
)
clusterer.fit(X_norm)
labels_cl = clusterer.labels_   # -1 = noise/outlier

n_clusters = len(set(labels_cl)) - (1 if -1 in labels_cl else 0)
n_noise    = (labels_cl == -1).sum()
print(f'  Clusters found: {n_clusters}')
print(f'  Noise points:   {n_noise:,}  ({n_noise/len(labels_cl)*100:.1f}%)')

# ── Characterize clusters ──────────────────────────────────────────────────────

print(f'\n{"="*70}')
print('CLUSTER CHARACTERIZATION')
print(f'{"="*70}')

# For each cluster, find:
#   1. Size and DLL composition
#   2. Most discriminating rules (high mean in cluster vs global mean)
#   3. Top example function names

global_mean = rule_matrix.astype(float).mean(axis=0)

cluster_ids = sorted(set(labels_cl.tolist()))
if -1 in cluster_ids:
    cluster_ids.remove(-1)

cluster_summaries = []

for cid in cluster_ids:
    mask    = labels_cl == cid
    n       = mask.sum()
    members = rule_matrix[mask].astype(float)

    # DLL composition
    dll_cnt = Counter(dll_labels[mask].tolist())

    # Most discriminating rules: cluster mean - global mean
    local_mean = members.mean(axis=0)
    lift       = local_mean - global_mean
    top_rule_idx = np.argsort(lift)[::-1][:5]

    # Example function names
    examples = fn_names[mask][:3].tolist()

    # Dominant rule expansions
    top_rules = [(int(top_rule_idx[i]),
                  float(lift[top_rule_idx[i]]),
                  str(rule_labels[top_rule_idx[i]]))
                 for i in range(5)]

    cluster_summaries.append({
        'id': int(cid),
        'n': int(n),
        'dll_dist': dict(dll_cnt.most_common(5)),
        'top_rules': top_rules,
        'examples': examples,
    })

cluster_summaries.sort(key=lambda x: -x['n'])

# Attempt to label cluster based on its most discriminating rules
def label_cluster(top_rules: list) -> str:
    rule_text = ' '.join(r[2] for r in top_rules).lower()
    if 'load_8 int_add_8 return' in rule_text or 'load_8 copy_8 int_add_8 return' in rule_text:
        return 'GETTER'
    if 'branchind' in rule_text:
        return 'DISPATCHER'
    if 'float_arith' in rule_text or 'float_cast' in rule_text:
        return 'FLOAT_COMPUTE'
    if 'bool_op_1 cbranch' in rule_text:
        return 'GUARD_COMPOUND'
    if 'int_equal_1' in rule_text and 'cbranch' in rule_text:
        return 'GUARD_SIMPLE'
    if 'store_16' in rule_text or 'load_16' in rule_text:
        return 'SIMD_COPY'
    if 'int_add_8 copy_8 store_8' in rule_text and 'load' not in rule_text:
        return 'WRITER'
    if 'int_add_8 load_8 copy_8' in rule_text:
        return 'READER'
    if 'call __sep__' in rule_text or 'callind __sep__' in rule_text:
        return 'CALLER'
    if 'copy_8 copy_8 copy_8' in rule_text:
        return 'REGISTER_HEAVY'
    if 'overflow_check' in rule_text or 'int_ucmp' in rule_text:
        return 'ARITHMETIC'
    return 'MIXED'

for cs in cluster_summaries:
    label = label_cluster(cs['top_rules'])
    top5_dlls = ', '.join(f'{d}({n})' for d, n in list(cs['dll_dist'].items())[:3])
    print(f'\nCluster {cs["id"]:>3}  [{label:<16}]  n={cs["n"]:>6,}')
    print(f'  DLLs: {top5_dlls}')
    print(f'  Top discriminating rules (lift over global mean):')
    for idx, lift_val, expansion in cs['top_rules'][:3]:
        disp = expansion[:70] + ('...' if len(expansion) > 70 else '')
        print(f'    +{lift_val:.3f}  {disp}')
    print(f'  Examples: {cs["examples"][0]}')

# ── Cluster × DLL heatmap ──────────────────────────────────────────────────────

print(f'\n{"="*70}')
print('CLUSTER × DLL DISTRIBUTION (fraction of DLL in each cluster)')
print(f'{"="*70}')

all_dlls = sorted(set(dll_labels.tolist()))
dll_totals = Counter(dll_labels.tolist())

# Header
header = f'{"Cluster":<10}' + ''.join(f'{d[:10]:<12}' for d in all_dlls)
print(header)
print('-' * len(header))

for cs in cluster_summaries[:20]:
    cid   = cs['id']
    label = label_cluster(cs['top_rules'])
    row = f'{cid:>3}[{label[:8]:<8}]'
    for dll in all_dlls:
        n_in_cl = cs['dll_dist'].get(dll, 0)
        frac    = n_in_cl / dll_totals[dll] if dll_totals[dll] > 0 else 0
        row += f'{frac*100:>10.1f}%  ' if frac > 0.01 else f'{"·":>10}   '
    print(row)

# Noise row
noise_mask = labels_cl == -1
noise_dll  = Counter(dll_labels[noise_mask].tolist())
row = f' -1[NOISE   ]'
for dll in all_dlls:
    n_in_cl = noise_dll.get(dll, 0)
    frac    = n_in_cl / dll_totals[dll] if dll_totals[dll] > 0 else 0
    row += f'{frac*100:>10.1f}%  ' if frac > 0.01 else f'{"·":>10}   '
print(row)

# ── Save cluster assignments ───────────────────────────────────────────────────

assignments = {
    'fn_names': fn_names.tolist(),
    'dll':      dll_labels.tolist(),
    'cluster':  labels_cl.tolist(),
    'cluster_labels': {
        str(cs['id']): label_cluster(cs['top_rules'])
        for cs in cluster_summaries
    }
}
with open('pcode_clusters.json', 'w') as f:
    json.dump(assignments, f)

print(f'\nCluster assignments → pcode_clusters.json')
print(f'SVD components saved in memory (rerun to regenerate)')
print(f'\nDone. Key findings above — look for DLL-specific cluster enrichment.')
