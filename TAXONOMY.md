# P-Code Function Taxonomy

Reference for the 141 structural clusters found in the 69,653-function corpus.
Archetypes are named by their dominant P-Code grammar pattern.

## Archetype Definitions

### CALLER
**Signature**: `(COPY_8)* INT_SUB_8 STORE_8 (CALL|CALLIND) __SEP__`  
**Meaning**: Sets up a stack frame, optionally saves registers, then calls another function and returns.  
**LLM budget**: LOW. These functions are largely boilerplate. Only explore if it's an entry point or the callee is interesting.  
**Appears in**: All DLLs. High fraction in QEMU (JIT dispatch), python312 (interpreter loop).

### READER
**Signature**: `INT_ADD_8 LOAD_8 COPY_8` or `INT_ADD_8 LOAD_4 COPY_4 INT_ZEXT_8`  
**Meaning**: Reads one or more struct/array fields. Access patterns directly reveal data layout.  
**LLM budget**: MEDIUM. Run struct_recover.py on these. The field offsets tell you the struct layout.  
**Appears in**: All DLLs, especially combase (COM interface reads) and esent (B-tree node reads).

### WRITER
**Signature**: `INT_ADD_8 COPY_8 STORE_8` or `INT_ADD_8 COPY_4 STORE_4`  
**Meaning**: Writes one or more struct/array fields. Combined with READER: identifies mutable state.  
**LLM budget**: MEDIUM. These tell you what fields are initialized/updated. T_field_type classifies each field.  
**Appears in**: mgba (GBA state writes), winhttp (HTTP session state), ntdll (NT object updates).

### GETTER
**Signature**: `LOAD_8 INT_ADD_8 RETURN __SEP__` or `COPY_8 LOAD_8 INT_ADD_8 RETURN __SEP__`  
**Meaning**: Accessor function — loads one field and returns it immediately. Very short.  
**LLM budget**: VERY LOW. The function name + return type is all you need. Skip body.  
**Appears in**: mgba (65% of GBA register accessors), kernelbase, crypt32.

### GUARD_SIMPLE
**Signature**: `CBRANCH __SEP__` with one comparison before it  
**Meaning**: Single entry condition. The function checks one thing and exits if it fails.  
**LLM budget**: LOW-MEDIUM. The constraint IS the information — T_field_type classifies what's being checked.  
**Appears in**: ntdll (28% — NT guards everything), dxgi (COM interface validation).

### GUARD_COMPOUND
**Signature**: `BOOL_OP_1 CBRANCH __SEP__` — multiple conditions combined  
**Meaning**: Policy validation — multiple conditions must all pass before proceeding.  
**LLM budget**: MEDIUM. The combination of conditions defines the invariant.  
**Appears in**: ntdll (dominant pattern — 12.1% of ntdll), rpcrt4 (RPC security).

### REGISTER_HEAVY
**Signature**: `COPY_8 COPY_8 COPY_8 COPY_8` chains, many COPY variants  
**Meaning**: Heavy register manipulation. Usually ABI glue, vtable dispatch boilerplate, or forwarding stubs.  
**LLM budget**: LOW. Mostly mechanical. Only interesting if the CALLIND target is revealing.  
**Appears in**: combase (14.9% — COM vtable ABI), dxgi (5.4% — forwarding stubs).

### SIMD_COPY
**Signature**: `INT_ADD_8 COPY_16 STORE_16`  
**Meaning**: 128-bit bulk copy operations. Struct initialization or bulk data movement using SSE/AVX.  
**LLM budget**: LOW. Struct initialization — use struct_recover.py instead of LLM.  
**Appears in**: kernelbase, dxgi, winhttp (TLS buffer initialization).

### ARITHMETIC
**Signature**: `INT_ADD_8 INT_MULT_8` chains without significant memory access  
**Meaning**: Pure integer computation. No dominant memory pattern. Algorithm implementation.  
**LLM budget**: HIGH. These encode domain algorithms — exactly what you want LLM to analyze.  
**Appears in**: linux_x264 (17% — encoder decision loops), esent (B-tree arithmetic).

### FLOAT_COMPUTE
**Signature**: `FLOAT_ARITH_8 FLOAT_ARITH_8` chains  
**Meaning**: Floating-point computation. Signal processing, physics, graphics.  
**LLM budget**: HIGH if domain-specific, LOW if standard math (sin, sqrt).  
**Appears in**: mgba (audio/DSP), linux_opus (CELT spectral computation).

### MIXED
**Signature**: No single dominant grammar rule  
**Meaning**: Complex function with diverse operations. Often the most algorithmically rich.  
**LLM budget**: HIGH. No single structural category — the complexity IS the information.  
**Appears in**: All DLLs. High in linux_x264 (11.6%) and mgba (7%).

### NOISE (unclassified)
**Meaning**: Matches no cluster with sufficient density. Structurally unique in the corpus.  
**LLM budget**: HIGHEST. These are the functions most unlike everything else we've seen.  
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

## Grammar Coverage as LLM Budget

```
coverage = fraction of 300 grammar rules matched by this function

0.00 ──── Novel ──────────────────────────────────── Explore (HIGH budget)
0.15
0.35 ──── Moderate ────────────────────────────────── Medium budget
0.50
0.60 ──── Predictable ──────────────────────────────── Classify cheaply (LOW budget)
1.00
```

DLL coverage rankings (lower = more novel):
- linux_ssl: 0.201 · linux_python: 0.213 · linux_sqlite: 0.245
- winhttp: 0.406 · crypt32: 0.410 · py_sqlite: 0.391

---

## Isolation Fraction as Exploration Priority

Functions with no resolvable static callees (computed dispatch, vtables, function pointers):

```
Low isolation (< 20%)  → well-characterized by static analysis → lower LLM priority
High isolation (> 40%) → statically opaque → HIGHEST LLM priority
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

**Case 2 — Computed dispatch target (highest educational value):**
Domain-specific functions called through function pointer tables, vtable slots, or
jump tables that Ghidra can't statically trace.

**The discriminant is the function's nature:**
- Standard utility functions (`wcsstr`, `memcmp`, etc.) are NEVER called via function
  pointers in normal code. If Ghidra sees 0 callers for these, it's Case 1 (dead code).
- Domain-specific functions (`ScpCfgHandleInvalidCallTarget`, ARM7 opcode handlers) ARE
  designed to be in dispatch tables. If Ghidra sees 0 callers, it's Case 2 (computed
  dispatch — highest LLM priority).

The indirect/function-pointer pattern is itself domain knowledge. State machines,
CPU emulators, COM vtables, JIT callbacks — these domains REQUIRE dispatch tables.
String utilities do not. The 0-caller pattern means different things depending on
what kind of function it is.

**Implication for LLM exploration budget:**
- Isolated utility function → dead code, skip (LLM recognizes by name)
- Isolated domain function → computed dispatch target, explore immediately
