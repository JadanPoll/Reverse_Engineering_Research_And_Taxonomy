# P-Code Structural Taxonomy Pipeline

Static analysis pipeline that turns any binary (PE/ELF/static lib) into a
**structural brief** — a Markdown document that gives an LLM everything it needs
to explore the binary efficiently with minimal inference hops.

## Quick Start

```bash
# 1. Run the full pipeline on current corpus
py -3.13 pcode_extractor.py       # lift P-Code from all targets
py -3.13 pcode_normalize.py       # level-1 normalization
py -3.13 pcode_grammar.py --corpus pcode_corpus_norm.jsonl --out pcode_grammar_norm.npz
py -3.13 pcode_cluster.py --grammar pcode_grammar_norm.npz
py -3.13 pcode_wl.py              # call-graph WL kernel

# 2. Generate a structural brief for any target
py -3.13 generate_brief.py advapi32
py -3.13 generate_brief.py linux_x264 --out briefs/linux_x264.md
py -3.13 generate_brief.py --all      # generate briefs/ for every target
```

## Pipeline Architecture

```
Binary (PE/ELF/.a)
       │
       ▼
pcode_extractor.py ──────────────────► pcode_corpus.jsonl
  • Lifts P-Code via pypcode              (token sequences per function)
  • Level-0 normalization                pcode_vectors.npz
  • Encodes output sizes: LOAD_8         (frequency vectors)
  • Supports: .dll .exe .so .a
       │
       ▼
pcode_normalize.py ──────────────────► pcode_corpus_norm.jsonl
  • Level-1 normalization                (normalized token sequences)
  • Prologue: (COPY_8)* INT_SUB_8 STORE_* → __PROLOGUE__
  • Epilogue: LOAD_8 INT_ADD_8 RETURN → __EPILOGUE__
  • Removes OVERFLOW_CHECK_1 (x86 flag artifact)
       │
       ▼
pcode_grammar.py ────────────────────► pcode_grammar_norm.npz
  • Sequitur grammar induction             (function × rule presence matrix)
  • Finds recurring P-Code idioms
  • Default: top 300 rules
       │
       ▼
pcode_cluster.py ────────────────────► pcode_clusters.json
  • Variance weighting p*(1-p)             (cluster assignments)
  • TruncatedSVD(300→30)
  • HDBSCAN(min_cluster_size=200)
  • Current: 141 clusters, 3.8% noise
       │
       ▼
pcode_wl.py ─────────────────────────► pcode_wl.json
  • Weisfeiler-Lehman kernel               (WL labels at depth 0-3)
  • Uses call graph from calltrees         (isolation flags)
  • Saturates at depth-2 (design patterns are 2-hop phenomena)
       │
       ▼
generate_brief.py ───────────────────► briefs/<label>.md
  • Synthesizes all above                  (LLM-consumable Markdown)
  • Archetype distribution
  • Grammar coverage (LLM budget predictor)
  • Exploration priority list
  • Domain fingerprint
```

## Normalization Levels

### Level-0 (in `pcode_extractor.py`) — always applied

Collapses compiler noise while preserving structural signal:

| Input opcodes | Normalized token | Rationale |
|---|---|---|
| FLOAT_ADD/SUB/MULT/DIV/SQRT/NEG/ABS/CEIL/FLOOR/ROUND | `FLOAT_ARITH` | All signal "float math" |
| FLOAT_EQUAL/NOTEQUAL/LESS/LESSEQUAL/NAN | `FLOAT_CMP` | All signal "float comparison" |
| FLOAT_INT2FLOAT/FLOAT2FLOAT/TRUNC | `FLOAT_CAST` | All signal "type conversion" |
| INT_CARRY/SCARRY/SBORROW | `OVERFLOW_CHECK` | x86 carry/overflow flags |
| INT_LESS/LESSEQUAL | `INT_UCMP` | Unsigned ordered comparison |
| INT_SLESS/SLESSEQUAL | `INT_SCMP` | Signed ordered comparison |
| INT_DIV/SDIV | `INT_DIVIDE` | Division (signed/unsigned) |
| INT_REM/SREM | `INT_MODULO` | Modulo (signed/unsigned) |
| BOOL_AND/OR/XOR/NEGATE | `BOOL_OP` | Compound conditional |
| MULTIEQUAL/INDIRECT/CAST/SEGMENTOP/CPOOLREF/NEW/IMARK | *(suppressed)* | SSA artifacts |
| POPCOUNT_1 | *(suppressed)* | x86 parity flag artifact (POPCOUNT_4/8 kept) |

**Output size encoding**: Every opcode gets `_N` suffix where N = output bytes.
`LOAD_8` vs `LOAD_4` vs `LOAD_1` carry different structural signal.
Output size chosen (not input) because output is the causal downstream signal.

### Level-1 (in `pcode_normalize.py`) — applied to normalized corpus

| Pattern | Replacement | Rationale |
|---|---|---|
| `(COPY_8)* INT_SUB_8 STORE_*` at function start | `__PROLOGUE__` | x86-64 callee-saved register saves |
| `LOAD_8 INT_ADD_8 RETURN` at function end | `__EPILOGUE__` | Stack restore + return |
| `OVERFLOW_CHECK_1` anywhere | *(removed)* | CF/OF flag always set by x86 arithmetic, not programmer-controlled |

## Adding New Targets

### PE/DLL (Windows)

1. Add to `discover_targets()` in `pcode_extractor.py` via the `extra_dlls` dict:
   ```python
   extra_dlls = {
       'mylib': 'C:/path/to/mylib.dll',
   }
   ```
   Or place calltree.json + mylib.dll in `TESTS/real_world/windows/mylib/`.

2. Re-run the full pipeline.

### ELF (.so, Linux shared library)

1. Add to `linux_libs/` (or use `get_linux_libs.py` for Debian packages).
2. Add to `ELF_LABELS` dict in `pcode_extractor.py`.
3. Architecture auto-detected from ELF header.

```python
ELF_LABELS = {
    'libmylib.so.1': 'my_label',
}
```

### Static library (.a, full internal symbols)

Best for stripped shared libraries where you want internal functions:

```python
STATIC_LABELS = {
    'libmylib.a': 'my_label',
}
```

Requires the `-dev` package. Extract with:
```bash
py -3.13 get_linux_libs.py   # add to WANT list in that script
```

### Zephyr RTOS / ARM firmware

1. Build ELF via GitHub Actions (see `zephyr_build.yml`)
2. Place `zephyr.elf` in `linux_libs/`
3. Add to `ELF_LABELS` — architecture auto-detected as `RISCV:LE:32:default`

## Key Output Files

| File | Contents | Used by |
|---|---|---|
| `pcode_corpus.jsonl` | Raw token sequences per function | pcode_normalize.py |
| `pcode_corpus_norm.jsonl` | Normalized token sequences | pcode_grammar.py |
| `pcode_grammar_norm.npz` | Function × rule presence matrix (300 rules) | pcode_cluster.py |
| `pcode_clusters.json` | Cluster assignment per function | generate_brief.py, pcode_wl.py |
| `pcode_wl.json` | WL labels (depth 0-3), isolation flags | generate_brief.py |
| `briefs/<label>.md` | Structural brief for each target | LLM context |

## Corpus State (2026-06-22)

- **69,653 functions** across 24 targets
- **18 PE** (Windows DLLs + emulators): advapi32, combase, crypt32, dxgi, esent,
  kernel32, kernelbase, ntdll, rpcrt4, schannel, vcruntime140, winhttp, ws2_32,
  mgba, python312, qemu_avr, qemu_i386, py_sqlite
- **4 ELF** (Linux .so): linux_ssl, linux_sqlite, linux_python, linux_libc
- **2 static** (Linux .a): linux_x264, linux_opus
- **Vocabulary**: 108 token types (compiler-invariant — same across MSVC and GCC)
- **Clustering**: 141 clusters, 3.8% noise (best achieved)

## Cross-Compiler Invariance

Empirically confirmed: GCC and MSVC produce the same 108 token types.
Cosine similarity between same-algorithm cross-compiler binaries:

| Pair | Similarity | Type |
|---|---|---|
| linux_python vs python312 | 0.958 | Same CPython source, GCC vs MSVC |
| linux_libc vs ntdll | 0.961 | Same domain, different impl |
| py_sqlite vs linux_sqlite | 0.962 | Same SQLite source, GCC vs MSVC |
| linux_ssl vs schannel | 0.859 | Same TLS domain, different impl |

**Implication**: Structural briefs trained on Windows DLLs apply to Linux .so files.

## Grammar Coverage as LLM Budget

`grammar_coverage(function)` = fraction of 300 grammar rules matched.

| Coverage | Interpretation | LLM budget |
|---|---|---|
| 0.00 | Matches no known pattern | HIGH — explore first |
| 0.10–0.20 | Structurally novel | HIGH |
| 0.20–0.35 | Moderate novelty | MEDIUM |
| 0.35–0.50 | Predictable | LOW |
| 0.50+ | Highly predictable | MINIMAL — classify only |

Coverage ordering by DLL (lower = more novel):
- linux_ssl: 0.201 · linux_python: 0.213 · linux_sqlite: 0.245 · linux_libc: 0.247
- python312: 0.306 · mgba: 0.338 · esent: 0.344
- crypt32: 0.410 · winhttp: 0.406 · py_sqlite: 0.391

## WL Kernel (Call Graph Context)

WL-2 design patterns are depth-2 call-graph neighborhoods.
Key finding: WL saturates at depth-2 (only 11% new labels at depth-3).
**Design patterns are 2-hop phenomena in real software.**

Isolation fraction (functions with no resolvable static callees):
- linux_opus: 2.4% · qemu_avr/i386: ~20% · mgba: 65.8%
- High isolation = statically opaque = highest LLM exploration priority

## Key Findings

1. **108 token types** — compiler-invariant vocabulary; saturated at 21 targets
2. **WL depth-2 saturation** — design patterns are 2-hop phenomena
3. **Grammar coverage = LLM budget predictor** — free, static, runs in seconds
4. **Cross-domain clustering** — mGBA + x264 + QEMU share dispatch-heavy archetype
5. **Codec entropy** — x264/Opus at 4.65-4.67 bits (highest in corpus) confirms novel structure
6. **Variance weighting p(1-p)** — correct null model for binary feature clustering
