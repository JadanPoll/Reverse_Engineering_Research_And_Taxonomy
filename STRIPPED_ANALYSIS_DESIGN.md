# Stripped Binary Analysis — Design Notes
*Written after Phase 1a runs 016-017. Decisions deferred until Phase 2 data exists.*

---

## The Core Problem

Every H-score gain in Phase 1 is a symbol-name win, not a reasoning win.
Strip the names and the current toolkit provides near-zero lift.
A fingerprint library (pre-annotating known patterns) is the wrong fix:
non-autonomous, requires constant curation, search space is explosive
(templates, inlining, callbacks, ABI variants). It also prevents the LLM
from being the reasoner — it becomes a reader of your annotations.

The right fix is a different architecture, not more annotations.

---

## The Framework: Shannon Interest Bits

Browser fingerprinting analogy: no single signal identifies a browser uniquely,
but OS + screen res + timezone + fonts + plugins + ... multiplied together does.
Same principle for binary functions. Each heuristic is a weak, noisy bit.
Their joint probability is highly discriminating.

**Key property:** each bit must be orthogonal. Correlated bits don't add information.
Templated code defeats xref-count (many callers per instantiation) but locality
recovers it (all instantiations cluster spatially). Use locality when xref is polluted.

### Structural Bits (static, near-free)

| Bit | Low interest signal | High interest signal |
|-----|--------------------|--------------------|
| Function size | < 20 instructions | > 100 instructions |
| Branch density | < 1 branch / 20 instrs | > 1 branch / 5 instrs |
| Call fan-out depth | Returns quickly to known-tagged territory | Deep call chains into unknown code |
| Xref count (callers) | Many callers → utility function | Few callers → decision spine |
| Return type character | Returns constant → error leaf | Returns pointer → decision path |
| Stack spill size | Register-only → simple | Large stack frame → complex state |
| Locality cluster | Dense STL/runtime zone | Application zone, isolated |

### Dynamic Bits (require execution, highest value)

| Bit | What it tells you |
|-----|------------------|
| Hot path frequency | Which functions matter in practice vs dead code |
| Input → output mapping | What it computes, not what it is |
| Control path coverage | Which branches are live under realistic inputs |
| Crash boundary | What input triggers first fault → what it validates |

### Semantic Tags (Ghidra/WinDbg give these free on imports)

Calls to tagged known functions betray the parent function's neighborhood.
Even an unnamed function that calls CryptHashData is in the crypto zone.
Even an unnamed function that calls WSASend is in the network zone.
Tag propagates up the call graph by proximity.

---

## H ≤ 5 as a Design Bound

The toolkit should be designed around making H ≤ 5 achievable for any question
in the class: stripped -O2, no debug info, real application code.

**H = 1–2: surface maximum data, make zero reasoning demands.**
The toolkit provides everything observable. The LLM reads, not reasons.
Output: interest scores, behavioral observations, tagged call targets, hot paths,
xref counts, structural measurements — all raw, no interpretation.

NOT: "this is a vector realloc"
YES: "function 0x10042a30: size=388, 3 callers, calls malloc/memcpy/free in
     sequence, hot (10k calls/run), STL locality cluster, returns void,
     stack spill 48 bytes"

The LLM interprets. The toolkit observes.

**H = 3–5: focused investigation on high-interest targets only.**
LLM drives: requests simulation of specific inputs, requests GDB traces at
specific addresses, requests string xrefs, requests call graph expansion.
The toolkit executes the requests. The LLM reasons over the results.

**H > 5: flag as unresolved, requires 3-way confirmation.**
Pure-math functions, heavily aliased pointer chains, cross-context state.
Without the static + memory + execution triangle, don't compound.

---

## The Overconfidence Fix

Current output: assertions ("this is _M_realloc_append").
Required output: scored claims with evidence.

```json
{
  "claim": "dynamic array growth function",
  "confidence": 0.72,
  "evidence": [
    {"bit": "calls malloc→memcpy→free in sequence", "weight": 0.40},
    {"bit": "caller branch checks two fields for equality first", "weight": 0.20},
    {"bit": "return value unused by caller", "weight": 0.12}
  ],
  "unconfirmed": ["capacity-doubling pattern not yet verified by execution"]
}
```

The LLM sees evidence structure, not conclusions. When confidence < threshold,
it knows to request dynamic confirmation before compounding. This is the only
autonomous fix — the LLM must be able to see its own uncertainty, not just
receive pre-chewed answers.

---

## Fast Path / Slow Path

**Fast path (interest scoring):** score every function in the calltree on
structural + dynamic bits. Rank by interest score. Present ranked list to LLM
so it can allocate investigation budget before reading pseudocode.

High interest: large function, many branches, deep calls into unknown territory,
few callers, calls to tagged domain APIs (crypto/network/file), complex stack.

Low interest: small, many callers, trivial branches, returns constant,
all calls resolve to known-tagged runtime functions. Skip or summarize.

**Slow path (deep analysis):** only for functions above interest threshold.
LLM-driven: iterative tool calls, simulation, GDB traces.

This is the attention mechanism for RE. The LLM shouldn't read everything equally.

---

## What Needs to Be Built (decision deferred to after Phase 2 data)

Priority ordering — do NOT build until Phase 2 strips show which bits are
actually discriminating vs which are noise.

1. **Interest scorer** — computes structural bits per function, emits into
   calltree JSON. ~200 lines in `ghidra_dump_calltree.py`. Highest leverage.

2. **Behavioral oracle** — auto-runs seeded functions with test inputs from
   `ground_truth.py`, embeds input/output pairs + hot path frequencies.
   Bridges stripped-code gap without fingerprinting. Autonomous.

3. **Confidence-scored output format** — replaces assertion-style TOOLKIT_NOTEs
   with scored claims + evidence. Propagates through calltree format and
   Q&A rubric.

4. **String xref chaining** — extends `resolve_pointer_entries`:
   any identified string traceable to full set of functions referencing it,
   with call distance. Strings are H=1 anchors that tag entire call graph
   neighborhoods.

5. **3-way confirmation wiring** — fractal_memscan + runtime_probe + static
   already exist but aren't wired to stripped analysis flow. Longest build,
   highest ceiling.

---

## The Pointer Problem

Hardest case. Pointers carry program state across contexts and time.
Resolving pointer provenance requires: allocation site, write sites,
read sites, transport (passed as arg, stored in struct, returned).

This is full dataflow analysis. Cannot be solved statically in optimized code.
Requires GDB as the closing instrument:
- Ghidra: identifies dereference sites (static)
- memscan: what value is at the address at runtime (memory)
- GDB: where that value was written, by what path (execution)

Each answers a different question. All three needed together for aliased pointers.

---

## Human Psychology in Binary Code

Programmers leave consistent traces:
- Related code grouped spatially → locality clusters
- Error paths are leaves: few instructions, constant return, single exit
- Decision spines: large, branchy, pointer-returning
- Framework/library usage creates call signature patterns
- Bounded function complexity (human readability constraint)
- Math-heavy code (crypto, signal processing) is structurally flat → simulation only

The question "how much psychology survives stripping" is empirical.
Phase 2 data will tell us which psychological traces survive -O2 optimization.
Inlining and loop unrolling attack spatial locality. Branch elimination attacks
branch density. But: allocation patterns, call target tags, stack frame complexity,
and the error-leaf / decision-spine dichotomy survive most optimizations.

The hard cases where psychology is erased: pure computation (hashing,
compression, signal processing). These are best attacked with simulation.
The easy cases where it survives: control flow heavy code, error handling,
dispatch tables, initialization sequences.

---

## What Phase 2 Will Tell Us

Run the same questions on stripped versions of Phase 1a DLLs.
The gap between Phase 1 H_actual and Phase 2 H_actual, per question,
tells us exactly which information was load-bearing. That's the calibration
data for the interest scorer and behavioral oracle.

Expected brutal jumps: cpp_stl_containers (run-017 avg_actual=1.33 → likely 3.5+).
Expected resilient: crypto_patterns, control_flow, api_hashing (behavioral fingerprints
survive stripping better than STL internal names).

Do not build anything from this document until Phase 2 data exists.
The data decides which bits matter.
