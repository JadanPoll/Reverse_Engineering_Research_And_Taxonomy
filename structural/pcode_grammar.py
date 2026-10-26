"""
pcode_grammar.py — Grammar induction on the P-Code corpus via Sequitur.

Pipeline:
  1. Load pcode_corpus.jsonl
  2. Run Sequitur on the full concatenated token stream (all 59K functions)
  3. Print the top grammar rules (the P-Code idiom lexicon)
  4. For each function, compute a rule-usage frequency vector
     (replaces raw token vector — captures n-gram structure, not just unigrams)
  5. Save grammar + function rule-vectors to pcode_grammar.npz for clustering

The rule-usage vector is the key output: each function becomes a point in
rule-space rather than token-space. Clustered functions share the same idioms,
not just the same opcodes.

Key insight from pilot run: Sequitur naturally compresses the x86 flag-update
block (OVERFLOW_CHECK_1 INT_SUB_8 INT_SCMP_1 INT_EQUAL_1 ...) into a single
rule. It will be down-weighted in clustering because it appears uniformly.
"""
import json, time, sys, re
from collections import Counter, defaultdict

import numpy as np
import sksequitur

sys.stdout.reconfigure(line_buffering=True)

CORPUS   = 'pcode_corpus.jsonl'
OUT_NPZ  = 'pcode_grammar.npz'
SEP      = '__SEP__'          # function boundary marker
MAX_RULE_EXPANSION = 12       # truncate long rule display at this many tokens
TOP_RULES = 300               # rules to keep for function vectors

# ── Load corpus ───────────────────────────────────────────────────────────────

import argparse
_ap = argparse.ArgumentParser()
_ap.add_argument('--corpus', default=CORPUS)
_ap.add_argument('--out',    default=OUT_NPZ)
_args = _ap.parse_args()
CORPUS  = _args.corpus
OUT_NPZ = _args.out

print(f'Loading corpus from {CORPUS}...')
records = []
with open(CORPUS, encoding='utf-8') as f:
    for line in f:
        records.append(json.loads(line))
print(f'  {len(records):,} functions loaded')

# ── Build global token stream ─────────────────────────────────────────────────

print('Building token stream...')
all_tokens = []
fn_slices  = []   # (start, end) indices in all_tokens for each function
for rec in records:
    start = len(all_tokens)
    all_tokens.extend(rec['tokens'])
    all_tokens.append(SEP)
    fn_slices.append((start, len(all_tokens)))

print(f'  Total tokens: {len(all_tokens):,}  (including {len(records):,} SEP markers)')

# ── Run Sequitur ──────────────────────────────────────────────────────────────

print('Running Sequitur grammar induction...')
t0 = time.perf_counter()
grammar = sksequitur.parse(all_tokens)
elapsed = time.perf_counter() - t0
print(f'  Done in {elapsed:.1f}s  |  {len(grammar):,} rules discovered')

# ── Expand rules to terminals ─────────────────────────────────────────────────

def expand_rule(grammar, prod, max_depth=8):
    """Fully expand a production to its terminal symbols (BFS, depth-limited)."""
    result = []
    for sym in grammar[prod]:
        if isinstance(sym, sksequitur.Production):
            # non-terminal: expand recursively (capped)
            result.extend(expand_rule(grammar, sym, max_depth - 1)
                          if max_depth > 0 else ['...'])
        else:
            result.append(str(sym))
    return result

# ── Print top rules ───────────────────────────────────────────────────────────

counts = grammar.counts()
print(f'\n{"="*65}')
print(f'TOP {TOP_RULES} GRAMMAR RULES — the P-Code idiom lexicon')
print(f'{"="*65}')
print(f'{"Rule":>6}  {"Count":>7}  Expansion')
print(f'{"-"*65}')

def _annotate(exp: list[str]) -> str:
    """Heuristic annotation of what a rule means."""
    s = ' '.join(exp)
    # Flag update blocks
    if 'OVERFLOW_CHECK' in s and 'INT_SCMP' in s and 'INT_EQUAL' in s:
        return 'x86 arithmetic flag-update block (CF+OF+SF+ZF+PF)'
    if 'INT_AND_1' in s and 'INT_SCMP_1' in s:
        return 'x86 flag computation artifact'
    # Memory patterns
    if re.search(r'INT_ADD_8.*(STORE_8|STORE_4)', s):
        return 'struct/array field WRITE'
    if re.search(r'INT_ADD_8.*LOAD_(8|4)', s):
        return 'struct/array field READ'
    if re.search(r'LOAD_8.*INT_EQUAL_1.*CBRANCH', s):
        return 'null pointer guard'
    if re.search(r'COPY_8.*INT_EQUAL_1.*CBRANCH', s):
        return 'value null-check guard'
    # Float
    if 'FLOAT_ARITH' in s:
        return 'floating-point computation'
    if 'FLOAT_CAST' in s:
        return 'float/int conversion'
    # Dispatch
    if 'BRANCHIND' in s:
        return 'indirect branch / dispatch'
    if all(t.startswith('COPY') for t in exp):
        return 'register spill / value shuffling'
    return ''

# ── Collect meaningful rules ──────────────────────────────────────────────────

rule_expansions = {}   # prod_id → list of terminal strings
meaningful_rules = []  # (count, prod_id) sorted desc

for prod, cnt in counts.most_common():
    if prod == 0:
        continue
    exp = expand_rule(grammar, prod)
    if all(t == SEP for t in exp):
        continue
    if len(exp) < 2:
        continue
    rule_expansions[prod] = exp
    meaningful_rules.append((cnt, prod))

meaningful_rules.sort(reverse=True)

for cnt, prod in meaningful_rules[:TOP_RULES]:
    exp = rule_expansions[prod]
    display = ' '.join(exp[:MAX_RULE_EXPANSION])
    if len(exp) > MAX_RULE_EXPANSION:
        display += ' ...'
    annotation = _annotate(exp)
    print(f'{int(prod):>6}  {cnt:>7,}  {display}')
    if annotation:
        print(f'{"":>6}  {"":>7}  → {annotation}')

# ── DLL distribution per rule ─────────────────────────────────────────────────

# For the top 30 rules, show which DLLs use them most
print(f'\n{"="*65}')
print(f'DLL DISTRIBUTION — which DLLs use each top rule')
print(f'{"="*65}')

# Build inverted index: which functions contain each terminal token pattern
# Strategy: for each function's token sequence, find which TOP rules appear
# by checking for the rule's terminal expansion as a subsequence.
# Approximate: check if ALL terminals of the rule appear in the function tokens.
# Exact would require scanning but is O(n*m*k) — too slow. Use approximate.

dll_rule_counts: dict[int, Counter] = defaultdict(Counter)

top30 = [prod for _, prod in meaningful_rules[:30]]

for rec in records:
    fn_tok_set = set(rec['tokens'])
    for prod in top30:
        exp_set = set(t for t in rule_expansions[prod] if t != SEP)
        if exp_set.issubset(fn_tok_set):
            dll_rule_counts[prod][rec['dll']] += 1

for cnt, prod in meaningful_rules[:15]:
    exp = rule_expansions[prod]
    display = ' '.join(exp[:6]) + ('...' if len(exp) > 6 else '')
    print(f'\nRule {int(prod)} (×{cnt:,}): {display}')
    for dll, n in dll_rule_counts[prod].most_common(5):
        print(f'  {dll:<25} {n:>5,}')

# ── Build function rule-usage vectors ─────────────────────────────────────────

print(f'\n{"="*65}')
print(f'Building function rule-usage vectors...')

# For each function, count how many times each TOP rule's tokens appear
# Use token-set membership as proxy for rule presence.
# More accurate: scan token sequence for exact rule expansion.

top_prods = [prod for _, prod in meaningful_rules[:TOP_RULES]]
prod_index = {p: i for i, p in enumerate(top_prods)}

# Pre-compute rule terminal sets for fast lookup
rule_term_sets = {prod: frozenset(t for t in rule_expansions[prod] if t != SEP)
                  for prod in top_prods}

n_fns  = len(records)
n_dims = TOP_RULES
rule_matrix = np.zeros((n_fns, n_dims), dtype=np.float32)
labels   = []
fn_names = []

for i, rec in enumerate(records):
    tok_set = set(rec['tokens'])
    for prod in top_prods:
        j = prod_index[prod]
        if rule_term_sets[prod].issubset(tok_set):
            rule_matrix[i, j] = 1.0
    labels.append(rec['dll'])
    fn_names.append(f"{rec['dll']}::{rec['fn']}")

    if i % 10000 == 0:
        print(f'  {i:>6}/{n_fns} functions processed...')

# L1-normalize
row_sums = rule_matrix.sum(axis=1, keepdims=True)
row_sums[row_sums == 0] = 1
rule_matrix_norm = rule_matrix / row_sums

print(f'  Rule matrix shape: {rule_matrix.shape}')
print(f'  Non-zero entries: {int(rule_matrix.astype(bool).sum()):,}  '
      f'({rule_matrix.astype(bool).mean()*100:.1f}% dense)')

# ── Save ──────────────────────────────────────────────────────────────────────

rule_ids    = np.array([int(p) for p in top_prods])
rule_labels = np.array([' '.join(rule_expansions[p][:8]) for p in top_prods])

np.savez_compressed(OUT_NPZ,
                    rule_matrix=rule_matrix,
                    rule_matrix_norm=rule_matrix_norm,
                    rule_ids=rule_ids,
                    rule_labels=rule_labels,
                    labels=np.array(labels),
                    fn_names=np.array(fn_names))

print(f'\nSaved → {OUT_NPZ}')
print(f'  rule_matrix:      {rule_matrix.shape}  (function × rule presence)')
print(f'  rule_matrix_norm: {rule_matrix_norm.shape}  (L1-normalized)')
print(f'  rule_labels:      {len(rule_labels)} rule expansions')
print(f'\nNext: python pcode_cluster.py')
