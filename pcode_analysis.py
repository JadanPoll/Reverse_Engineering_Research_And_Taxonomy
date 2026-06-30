"""
pcode_analysis.py — Quick analyses that don't need user input.

1. Power law check on grammar rule frequencies
2. Cross-compiler pair analysis: py_sqlite vs linux_sqlite
3. Per-function grammar compression ratio
"""
import json, math
import numpy as np
from collections import Counter
from scipy import stats

print('=' * 60)
print('ANALYSIS 1: Power law in grammar rule frequencies')
print('=' * 60)

# Load grammar results
data = np.load('pcode_grammar_norm.npz', allow_pickle=True)
rule_labels = data['rule_labels']
matrix      = data['rule_matrix']

# Rule frequency = how many functions use each rule
rule_freq = matrix.astype(bool).sum(axis=0)
rule_freq_sorted = np.sort(rule_freq)[::-1]

# Fit power law: log(freq) = -alpha * log(rank) + const
ranks = np.arange(1, len(rule_freq_sorted) + 1)
mask  = rule_freq_sorted > 0
log_ranks = np.log(ranks[mask])
log_freqs = np.log(rule_freq_sorted[mask])

slope, intercept, r, p, _ = stats.linregress(log_ranks, log_freqs)
print(f'  Power law fit: freq ~ rank^{slope:.3f}')
print(f'  R² = {r**2:.3f}  (1.0 = perfect power law)')
print(f'  Zipf law (text) predicts slope ≈ -1.0')
print(f'  Our slope: {slope:.3f} — ', end='')
if abs(slope + 1.0) < 0.2:
    print('close to Zipf → preferential attachment mechanism')
elif slope > -0.5:
    print('shallower than Zipf → more uniform distribution')
else:
    print('steeper than Zipf → more concentrated in top rules')

# Top 10 and bottom 10 rules
print(f'\n  Top 10 most-used rules:')
top10 = np.argsort(rule_freq)[::-1][:10]
for i, idx in enumerate(top10):
    exp = str(rule_labels[idx])[:50]
    print(f'    #{i+1:>2}  n={rule_freq[idx]:>6,}  {exp}')

print(f'\n  Least-used rules (still in top-80):')
bot5 = np.argsort(rule_freq)[:5]
for idx in bot5:
    exp = str(rule_labels[idx])[:50]
    print(f'    n={rule_freq[idx]:>6,}  {exp}')


print()
print('=' * 60)
print('ANALYSIS 2: Cross-compiler pair — py_sqlite vs linux_sqlite')
print('=' * 60)

labels = data['labels']
fn_names = data['fn_names']

mask_win = labels == 'py_sqlite'
mask_lin = labels == 'linux_sqlite'

print(f'  py_sqlite (MSVC):    {mask_win.sum():,} functions')
print(f'  linux_sqlite (GCC):  {mask_lin.sum():,} functions')

# Mean rule-usage profiles
mean_win = matrix[mask_win].astype(float).mean(axis=0)
mean_lin = matrix[mask_lin].astype(float).mean(axis=0)

# Cosine similarity
dot  = np.dot(mean_win, mean_lin)
norm = np.linalg.norm(mean_win) * np.linalg.norm(mean_lin)
cos  = dot / norm if norm > 0 else 0
print(f'\n  Cosine similarity (rule-usage profiles): {cos:.3f}')
print(f'  (same-algorithm cross-compiler reference: ~0.96)')

# Most divergent rules
diff = mean_win - mean_lin
top_win = np.argsort(diff)[::-1][:5]  # rules more common in MSVC
top_lin = np.argsort(diff)[:5]         # rules more common in GCC

print(f'\n  Rules MORE common in MSVC (py_sqlite):')
for idx in top_win:
    exp = str(rule_labels[idx])[:55]
    print(f'    MSVC={mean_win[idx]:.2f}  GCC={mean_lin[idx]:.2f}  {exp}')

print(f'\n  Rules MORE common in GCC (linux_sqlite):')
for idx in top_lin:
    exp = str(rule_labels[idx])[:55]
    print(f'    GCC={mean_lin[idx]:.2f}  MSVC={mean_win[idx]:.2f}  {exp}')


print()
print('=' * 60)
print('ANALYSIS 3: Per-function grammar compression ratio')
print('=' * 60)
# Compression ratio: how many of a function's token types are captured
# by our top-80 grammar rules (as presence fraction)
# High coverage = function is "common" (well-described by grammar)
# Low coverage  = function is "novel" (grammar doesn't describe it well)

coverage = matrix.astype(float).mean(axis=1)  # fraction of 80 rules present

print(f'  Mean coverage across all functions: {coverage.mean():.3f}')
print(f'  Std dev: {coverage.std():.3f}')
print(f'  Median:  {np.median(coverage):.3f}')

# Coverage by DLL
all_dlls = sorted(set(labels.tolist()))
print(f'\n  Coverage per DLL (mean fraction of grammar rules matched):')
for dll in all_dlls:
    m = labels == dll
    c = coverage[m].mean()
    std = coverage[m].std()
    print(f'    {dll:<20} {c:.3f} ± {std:.3f}')

# Functions with lowest coverage = most novel = highest LLM priority
print(f'\n  Most novel functions (lowest grammar coverage = explore first):')
novel_idx = np.argsort(coverage)[:10]
for idx in novel_idx:
    print(f'    coverage={coverage[idx]:.3f}  {fn_names[idx]}')

print(f'\n  Most common functions (highest grammar coverage = skip or classify cheaply):')
common_idx = np.argsort(coverage)[::-1][:10]
for idx in common_idx:
    print(f'    coverage={coverage[idx]:.3f}  {fn_names[idx]}')

print('\nDone.')
