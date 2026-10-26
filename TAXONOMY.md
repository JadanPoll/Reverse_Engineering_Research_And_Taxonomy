# P-Code Function Taxonomy

Reference for the 141 structural clusters found in the 69,653-function corpus.
Archetypes are named by their dominant P-Code grammar pattern.

## Archetype Definitions

### CALLER
**Signature**: `(COPY_8)* INT_SUB_8 STORE_8 (CALL|CALLIND) __SEP__`  
**Meaning**: Sets up a stack frame, optionally saves registers, then calls another function and returns.  
**Expected reasoning cost if relevant**: LOW. Usually mechanical delegation; inspect deeply only when the active question depends on the caller/callee relationship.  
**Appears in**: All DLLs. High fraction in QEMU (JIT dispatch), python312 (interpreter loop).

### READER
**Signature**: `INT_ADD_8 LOAD_8 COPY_8` or `INT_ADD_8 LOAD_4 COPY_4 INT_ZEXT_8`  
**Meaning**: Reads one or more struct/array fields. Access patterns directly reveal data layout.  
**Expected reasoning cost if relevant**: MEDIUM. Prefer structural field recovery before asking an LLM to infer layout from pseudocode.  
**Appears in**: All DLLs, especially combase (COM interface reads) and esent (B-tree node reads).

### WRITER
**Signature**: `INT_ADD_8 COPY_8 STORE_8` or `INT_ADD_8 COPY_4 STORE_4`  
**Meaning**: Writes one or more struct/array fields. Combined with READER: identifies mutable state.  
**Expected reasoning cost if relevant**: MEDIUM. Field writes are useful state evidence; deterministic field recovery should do the clerical work first.  
**Appears in**: mgba (GBA state writes), winhttp (HTTP session state), ntdll (NT object updates).

### GETTER
**Signature**: `LOAD_8 INT_ADD_8 RETURN __SEP__` or `COPY_8 LOAD_8 INT_ADD_8 RETURN __SEP__`  
**Meaning**: Accessor function — loads one field and returns it immediately. Very short.  
**Expected reasoning cost if relevant**: VERY LOW. Often an accessor; the body rarely deserves deep reasoning unless the question specifically concerns the field semantics.  
**Appears in**: mgba (65% of GBA register accessors), kernelbase, crypt32.

### GUARD_SIMPLE
**Signature**: `CBRANCH __SEP__` with one comparison before it  
**Meaning**: Single entry condition. The function checks one thing and exits if it fails.  
**Expected reasoning cost if relevant**: LOW-MEDIUM. The condition often carries most of the useful information.  
**Appears in**: ntdll (28% — NT guards everything), dxgi (COM interface validation).

### GUARD_COMPOUND
**Signature**: `BOOL_OP_1 CBRANCH __SEP__` — multiple conditions combined  
**Meaning**: Policy validation — multiple conditions must all pass before proceeding.  
**Expected reasoning cost if relevant**: MEDIUM. The conjunction/disjunction of conditions is often the main semantic evidence.  
**Appears in**: ntdll (dominant pattern — 12.1% of ntdll), rpcrt4 (RPC security).

### REGISTER_HEAVY
**Signature**: `COPY_8 COPY_8 COPY_8 COPY_8` chains, many COPY variants  
**Meaning**: Heavy register manipulation. Usually ABI glue, vtable dispatch boilerplate, or forwarding stubs.  
**Expected reasoning cost if relevant**: LOW for ordinary ABI glue; potentially higher when indirect dispatch is itself consequential to the question.  
**Appears in**: combase (14.9% — COM vtable ABI), dxgi (5.4% — forwarding stubs).

### SIMD_COPY
**Signature**: `INT_ADD_8 COPY_16 STORE_16`  
**Meaning**: 128-bit bulk copy operations. Struct initialization or bulk data movement using SSE/AVX.  
**Expected reasoning cost if relevant**: LOW. Prefer deterministic structure recovery to manual LLM interpretation.  
**Appears in**: kernelbase, dxgi, winhttp (TLS buffer initialization).

### ARITHMETIC
**Signature**: `INT_ADD_8 INT_MULT_8` chains without significant memory access  
**Meaning**: Pure integer computation. No dominant memory pattern. Algorithm implementation.  
**Expected reasoning cost if relevant**: HIGH. Pure computation can require semantic reasoning, but relevance still comes from the active question.  
**Appears in**: linux_x264 (17% — encoder decision loops), esent (B-tree arithmetic).

### FLOAT_COMPUTE
**Signature**: `FLOAT_ARITH_8 FLOAT_ARITH_8` chains  
**Meaning**: Floating-point computation. Signal processing, physics, graphics.  
**Expected reasoning cost if relevant**: variable. Domain-specific numerical code can be expensive; recognizable standard math is cheap.  
**Appears in**: mgba (audio/DSP), linux_opus (CELT spectral computation).

### MIXED
**Signature**: No single dominant grammar rule  
**Meaning**: Complex function with diverse operations. Often the most algorithmically rich.  
**Expected reasoning cost if relevant**: HIGH. Mixed structure gives the static machinery fewer shortcuts.  
**Appears in**: All DLLs. High in linux_x264 (11.6%) and mgba (7%).

### NOISE (unclassified)
**Meaning**: Matches no cluster with sufficient density. Structurally unique in the corpus.  
**Expected reasoning cost if relevant**: HIGHEST/UNCERTAIN. Lack of a cluster match means the existing structural vocabulary predicts poorly; it does not imply importance.  
**Appears in**: mgba (4.7%), linux_x264 (6.8%), linux_ssl (2.7%).

---

## Domain Fingerprints

Heuristic signatures based on archetype distribution:

| Fingerprint | Indicator | Example |
|---|---|---|
| Validation-heavy | GUARD > 30% | ntdll, rpcrt4 |
| Accessor-dominated | GETTER > 25% | mgba, kernelbase |
| Dispatch-heavy | CALLER > 35% | qemu_avr, qemu_i386 |
| State-mutation | WRITER > 25% | winhttp, schannel |
| Algorithm-rich | ARITHMETIC > 20% | linux_x264, linux_opus |
| Statically opaque | Isolation > 40% | mgba, any emulator |
| Codec/DSP | Entropy > 4.5 bits | linux_x264, linux_opus |

---

## Cross-Domain Clusters (Notable)

Some clusters span multiple DLLs from different domains, revealing universal structural patterns:

**Dispatch-heavy cluster**: mgba + linux_x264 + qemu_avr  
→ All use computed dispatch (jump tables, function pointers). Same structural pattern regardless of domain.

**TLS/protocol reader cluster**: winhttp + linux_libc + qemu_i386  
→ Struct field read with immediate conditional check. Universal "read-and-validate" pattern.

**Null-guard cluster**: ntdll + linux_libc + linux_sqlite (ntdll dominant at 500 fns)  
→ Simple BOOL_OP_1 CBRANCH — null/error check before proceeding. Universal C idiom.

**Codec internal reader**: linux_x264 + linux_opus + winhttp  
→ INT_ADD_8 LOAD_8 pattern for reading codec state fields. Same idiom across codecs and HTTP.

---

## WL-2 Design Patterns

Beyond individual function archetypes, call-graph context reveals design patterns:

| Pattern | Description | Primary DLL |
|---|---|---|
| PURE_GUARD | Guard function with no callees | ntdll (dominant) |
| LEAF_GETTER | Getter with no callees | mgba, python312 |
| GUARDED_READER | Reader calling Reader + Guard | winhttp (100% exclusive — TLS negotiation) |
| SIMD_C→WRITER | SIMD copy then struct write | dxgi, kernelbase |
| GETTER→GETTER | Accessor chain | crypt32 (DER field access) |
| REGISTER→CALLER | Register-heavy then call | combase (88.7% — COM vtable ABI) |
| READER→UNKNOWN | Reader calling unresolvable target | combase (99.4% — COM vtable dispatch) |
| ISOLATED_CALLER | Caller with no resolvable callees | QEMU (JIT-compiled code) |

---

## Grammar Coverage as Structural Predictability

```
coverage = fraction of 300 grammar rules matched by this function

0.00 ──── structurally unusual ───────────── high expected reasoning uncertainty
0.35 ──── moderate ───────────────────────── medium expected cost
0.60 ──── predictable ────────────────────── usually cheaper to interpret
1.00
```

Coverage is an **investigation-cost prior**, not an importance score. A predictable
function may be central to the question, while a novel function may be irrelevant.
The useful routing quantity is question relevance and expected uncertainty reduction
relative to the cost of obtaining the evidence.

DLL coverage rankings (lower = more structurally novel):
- linux_ssl: 0.201 · linux_python: 0.213 · linux_sqlite: 0.245
- winhttp: 0.406 · crypt32: 0.410 · py_sqlite: 0.391

---

## Isolation Fraction as Static-Opacity Signal

Functions with no resolvable static callees (computed dispatch, vtables, function pointers):

```
Low isolation (< 20%)  → static call relationships are comparatively informative
High isolation (> 40%) → static call relationships are incomplete; targeted dynamic evidence may have higher value
```

| DLL | Isolation | Why |
|---|---|---|
| mgba | 65.8% | ARM7 opcode dispatch through jump tables |
| kernel32 | 34.4% | Forwarding stubs to kernelbase |
| advapi32 | 36.4% | Mixed stubs and complex dispatch |
| winhttp | 14.7% | Clean static call structure |
| linux_opus | 2.4% | Very low — Opus has clean static call graph |

## Isolated Nodes: Dead Code vs Computed Dispatch

Functions with 0 resolvable callers AND 0 callees can be one of two things:

**Case 1 — Dead code from static CRT linking:**
Standard utility functions (`wcsstr`, `strchr`, `htonl`, `DebugBreak`) pulled in via
object-file-granularity linking. When a DLL links the CRT statically, the linker pulls
entire .obj files — if one function in the .obj is needed, all others come along. Without
/OPT:REF dead code elimination, these appear in the binary with no callers.

**Case 2 — Possible computed-dispatch target (higher static uncertainty):**
Domain-specific functions called through function pointer tables, vtable slots, or
jump tables that Ghidra can't statically trace.

**The discriminant is the function's nature:**
- Standard utility functions (`wcsstr`, `memcmp`, etc.) are often ordinary linked helpers; zero callers makes dead/unreached code plausible, but does not prove it.
- Domain-specific handlers, callbacks, vtable methods, or opcode handlers are more plausibly reached through indirect dispatch. Zero visible callers therefore raises the value of checking dispatch evidence when the active question depends on them.

The indirect/function-pointer pattern is itself domain knowledge. State machines,
CPU emulators, COM vtables, JIT callbacks — these domains REQUIRE dispatch tables.
String utilities do not. The 0-caller pattern means different things depending on
what kind of function it is.

**Implication for investigation routing:**
- Isolated utility-like function → cheap prior toward linked/dead/infrastructure code; verify only if relevant.
- Isolated domain-like function → static reachability is uncertain; consider vtable/jump-table/runtime evidence if the active question touches it.
