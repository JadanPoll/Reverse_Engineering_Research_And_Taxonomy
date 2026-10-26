"""
pcode_normalize.py — Apply level-1 normalization to pcode_corpus.jsonl.

Level-0 normalization (already done in pcode_extractor.py):
  - Float grouping, bool grouping, suppression of SSA artifacts

Level-1 normalization (this script):
  1. PROLOGUE abstraction: strip leading (COPY_8)* INT_SUB_8 STORE_8 → __PROLOGUE__
     These are x86-64 callee-saved register saves + stack adjustment.
     Responsible for 8+ redundant CALLER cluster variants.

  2. EPILOGUE abstraction: strip trailing LOAD_8 INT_ADD_8 RETURN → __EPILOGUE__
     The stack restore + return sequence. Mirror of prologue.

  3. OVERFLOW_CHECK_1 suppression: remove from all sequences.
     Ghidra emits CF/OF flag updates after every ADD/SUB/MULT regardless of
     programmer intent. Appears in every DLL at proportional-to-arithmetic-ops
     rate — zero discriminating power, pure noise at our analysis level.
     (cf. POPCOUNT_1 suppression in level-0)

Why separate from extractor: avoids re-lifting 65K functions (~2 min saved).
Preserves original corpus for comparison. Can test both versions.
"""
import json, re, sys
from collections import Counter

sys.stdout.reconfigure(line_buffering=True)

IN_CORPUS  = 'pcode_corpus.jsonl'
OUT_CORPUS = 'pcode_corpus_norm.jsonl'

def strip_prologue(tokens: list[str]) -> tuple[list[str], bool]:
    """Strip leading (COPY_8)* INT_SUB_8 STORE_8 → return (stripped_tokens, had_prologue)."""
    i = 0
    while i < len(tokens) and tokens[i] == 'COPY_8':
        i += 1
    # Must have consumed at least 0 COPYs and then see INT_SUB_8 STORE_8
    if i + 1 < len(tokens) and tokens[i] == 'INT_SUB_8' and tokens[i+1].startswith('STORE_'):
        return ['__PROLOGUE__'] + tokens[i+2:], True
    return tokens, False


def strip_epilogue(tokens: list[str]) -> tuple[list[str], bool]:
    """Strip trailing (COPY_8)? LOAD_8 INT_ADD_8 RETURN → append __EPILOGUE__."""
    t = tokens
    # Pattern: ... LOAD_8 INT_ADD_8 RETURN   (standard x86-64 epilogue)
    if len(t) >= 3 and t[-1] == 'RETURN' and t[-2] == 'INT_ADD_8' and t[-3] == 'LOAD_8':
        return t[:-3] + ['__EPILOGUE__'], True
    # Pattern: ... COPY_8 LOAD_8 INT_ADD_8 RETURN  (with extra copy)
    if len(t) >= 4 and t[-1] == 'RETURN' and t[-2] == 'INT_ADD_8' \
            and t[-3] == 'LOAD_8' and t[-4] == 'COPY_8':
        return t[:-4] + ['__EPILOGUE__'], True
    return tokens, False


def remove_overflow_checks(tokens: list[str]) -> list[str]:
    """Remove OVERFLOW_CHECK_1 — x86 CF/OF flag artifact, zero discriminating power."""
    return [t for t in tokens if t != 'OVERFLOW_CHECK_1']


# ── Stats tracking ─────────────────────────────────────────────────────────────

n_total = n_prologue = n_epilogue = n_overflow = 0
len_before = len_after = 0

print(f'Normalizing {IN_CORPUS} → {OUT_CORPUS}')
print('Applying: prologue abstraction + epilogue abstraction + OVERFLOW_CHECK_1 removal')

with open(IN_CORPUS, encoding='utf-8') as fin, \
     open(OUT_CORPUS, 'w', encoding='utf-8') as fout:

    for line in fin:
        rec = json.loads(line)
        tokens = rec['tokens']
        len_before += len(tokens)

        # Level-1 normalizations
        tokens, had_prologue = strip_prologue(tokens)
        tokens, had_epilogue = strip_epilogue(tokens)
        before_ov = len(tokens)
        tokens = remove_overflow_checks(tokens)

        n_total    += 1
        n_prologue += int(had_prologue)
        n_epilogue += int(had_epilogue)
        n_overflow += before_ov - len(tokens)
        len_after  += len(tokens)

        rec['tokens'] = tokens
        rec['n_ops']  = len(tokens)
        fout.write(json.dumps(rec) + '\n')

print(f'\nResults:')
print(f'  Functions processed:      {n_total:>10,}')
print(f'  Prologue stripped:        {n_prologue:>10,}  ({n_prologue/n_total*100:.1f}%)')
print(f'  Epilogue stripped:        {n_epilogue:>10,}  ({n_epilogue/n_total*100:.1f}%)')
print(f'  OVERFLOW_CHECK_1 removed: {n_overflow:>10,}  tokens')
print(f'  Tokens before:            {len_before:>10,}')
print(f'  Tokens after:             {len_after:>10,}  ({(1-len_after/len_before)*100:.1f}% reduction)')
print(f'\nNormalized corpus → {OUT_CORPUS}')
print('Next: py -3.13 pcode_grammar.py --corpus pcode_corpus_norm.jsonl')
