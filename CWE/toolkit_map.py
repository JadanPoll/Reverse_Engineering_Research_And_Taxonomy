"""
toolkit_map.py — Lateral translation of native-code CWEs into RE toolkit questions.

For each CWE: not "can we detect this vulnerability" but
"what binary information structure does this inspire us to capture?"

Categories:
  A = Already addressed by our toolkit
  B = Low-hanging fruit, buildable now
  C = Architecturally significant gap (requires data flow / lifetime tracking)
  D = Out of scope for binary RE / irrelevant

Usage: py -3.13 CWE/toolkit_map.py [--filter A|B|C|D]
"""

TRANSLATIONS = [

    # ── CALL / CALLING CONVENTION ─────────────────────────────────────────────

    ("130", "Improper Handling of Length Parameter Inconsistency",
     "B", "MEM+CALL",
     "Can we detect when a length argument doesn't correspond to the actual buffer "
     "size being operated on? Preamble analysis: is there a check that len <= sizeof(buf) "
     "before the operation? If not, the length is trusted implicitly."),

    ("134", "Use of Externally-Controlled Format String",
     "A", "CALL",
     "Already handled: variadic_format annotator fires when format string position "
     "has more % specifiers than captured args. Gap: we don't track whether the "
     "format string POSITION is user-controlled vs. hardcoded."),

    ("457", "Use of Uninitialized Variable",
     "B", "CALL",
     "Frida register_tracer captures register state at function entry. If a callee "
     "reads a register that the caller never wrote (garbage value), that register "
     "was uninitialized. Distribution of observed values for that arg: if entropy "
     "is maximal and not clustered → likely uninitialized."),

    ("685", "Function Call With Incorrect Number of Arguments",
     "B", "CALL",
     "Our param_count in func_info vs. what callers actually pass (from call graph). "
     "Mismatch between caller's named_callees arg count and callee's param_count "
     "signals ABI mismatch. Frida: n_args_detected in Tier3 vs. declared param_count."),

    ("562", "Return of Stack Variable Address",
     "B", "CALL+MEM",
     "Frida register_tracer: capture RSP at entry, RAX at exit. "
     "If RAX ∈ [RSP_entry, RSP_entry + frame_size] → returning stack address. "
     "Trivially detectable. Also indicates lifetime problem (stack frame gone after return)."),

    # ── MEMORY ────────────────────────────────────────────────────────────────

    ("119", "Improper Restriction of Operations within Buffer Bounds",
     "B", "MEM",
     "call_buffer() + guard pages already detects overflows at runtime. "
     "Static: does the function take (buf, len) and use len as a bound on writes? "
     "Or does it write up to a sentinel (strcpy pattern)?"),

    ("120", "Buffer Copy without Checking Size of Input",
     "B", "MEM",
     "Named callee detection: strcpy/strcat/gets/sprintf calls without a prior "
     "size check → flag. Already in named_callees. One lookup table away."),

    ("131", "Incorrect Calculation of Buffer Size",
     "C", "MEM+TYPE",
     "Arithmetic before malloc: is the allocation size computed with potential overflow? "
     "Requires tracking the arithmetic expression that feeds into the size argument "
     "of malloc/calloc. Interprocedural data flow — architecturally hard."),

    ("188", "Reliance on Data/Memory Layout",
     "A", "MEM",
     "Already handled: struct field propagation via emit_field_access. When code "
     "assumes struct fields are at specific offsets (pointer arithmetic), our "
     "annotate_field_accesses injects /* ->field_name */ comments."),

    ("244", "Improper Clearing of Heap Memory Before Release",
     "B", "MEM",
     "Detect memset/bzero calls that occur before free(). Or: absence of memset "
     "before free() on a buffer that previously held sensitive data. "
     "Callee sequence: [process_sensitive_data] → [free] without [memset] between."),

    ("401", "Missing Release of Memory",
     "C", "MEM",
     "malloc without free on all exit paths. Requires tracking which paths through "
     "a function have a matching free() for every malloc(). Interprocedural + "
     "control-flow sensitive. Hard without data flow."),

    ("415", "Double Free",
     "C", "MEM",
     "Same pointer freed twice. Requires pointer identity tracking across calls. "
     "Lifetime analysis — architecturally out of reach with current tools. "
     "Frida: hook free(), track pointer set, detect duplicates."),

    ("416", "Use After Free",
     "C", "MEM",
     "Pointer used after free() on same pointer. Pure lifetime tracking — "
     "hardest class. Frida: hook malloc/free, map pointer → lifetime window, "
     "detect access outside window. Theoretically doable with hooks but expensive."),

    ("466", "Return of Pointer Value Outside of Expected Range",
     "B", "MEM",
     "What is the expected range for a returned pointer? If function always returns "
     "a pointer into a known struct (e.g., member of a table), and returns NULL on "
     "error — this is detectable from return value distribution. classify.run() "
     "sentinel_frac captures the NULL-return pattern."),

    ("476", "NULL Pointer Dereference",
     "B", "MEM",
     "Preamble null check analysis: enumerate all pointer parameters, check which "
     "have null guards in the preamble. Parameters that are dereferenced without "
     "prior null check → potential null deref site. Statically analyzable from "
     "pseudocode patterns: `*param_1` without preceding `if (param_1 == NULL)`."),

    ("562", "Return of Stack Variable Address",
     "B", "MEM",
     "See CALL section. Stack address detection via Frida RSP comparison."),

    ("587", "Assignment of a Fixed Address to a Pointer",
     "B", "MEM",
     "Literal address assignment: `ptr = (type*)0x12345678`. "
     "Pattern-matchable in pseudocode: pointer-typed variable assigned a numeric "
     "literal that looks like an address (> PAGE_SIZE, aligned). Already partially "
     "covered by annotate_win32_constants for known addresses."),

    ("680", "Integer Overflow to Buffer Overflow",
     "C", "TYPE+MEM",
     "Multiplication/addition → malloc. The overflow happens in the size calculation "
     "before allocation. Requires arithmetic tracking into malloc size argument. "
     "Algebraic degree metric hints at this (complex arithmetic = higher degree) "
     "but doesn't give location."),

    ("787", "Out-of-bounds Write",
     "B", "MEM",
     "call_buffer guard pages catch this at runtime. Static: write index not "
     "bounds-checked before use. Similar to CWE-120 — look for array index "
     "without prior range check in preamble or surrounding code."),

    ("822", "Untrusted Pointer Dereference",
     "C", "MEM",
     "Pointer value comes from external source (network, file, user input) and "
     "is dereferenced without validation. Pure data flow from source to sink — "
     "requires taint tracking across function calls."),

    ("824", "Access of Uninitialized Pointer",
     "B", "MEM",
     "Pointer variable declared but not initialized before use. "
     "Pseudocode pattern: `undefined8 *puVar1; ... *puVar1 = something;` without "
     "an assignment to puVar1 first. Ghidra's `undefined` type annotations already "
     "mark these explicitly — this is detectable from pseudocode."),

    ("843", "Access of Resource Using Incompatible Type (Type Confusion)",
     "C", "TYPE",
     "Pointer cast to incompatible type, then dereferenced. RTTI/vtable case "
     "we already identified as H=3. Static analysis can flag explicit casts "
     "(int*) → (struct Foo*) but proving incompatibility requires type system."),

    # ── TYPE / ARITHMETIC ─────────────────────────────────────────────────────

    ("190", "Integer Overflow or Wraparound",
     "B", "TYPE",
     "algebraic_degree already hints at arithmetic complexity. More specific: "
     "look for multiplication that feeds into malloc/array index without overflow "
     "check. The preamble might have the check — if not, the arithmetic is trusted. "
     "Our signed_char_negation annotator handles the display side; detection is harder."),

    ("194", "Unexpected Sign Extension",
     "B", "TYPE",
     "SIGN_EXT_FRAC in runtime_probe already detects 32→64 bit sign extension "
     "in return values. Extend: detect when a short/int is used as array index "
     "after being widened (sign extension on negative value → huge index)."),

    ("195", "Signed to Unsigned Conversion Error",
     "A", "TYPE",
     "annotate_signed_negatives already handles display of -0x56 as 0xAA. "
     "Detection: comparison of signed value in unsigned context without cast. "
     "Look for `if (len >= 0)` on a signed variable — always true."),

    ("197", "Numeric Truncation Error",
     "B", "TYPE",
     "Value narrowed from larger to smaller type, losing high bits. "
     "Pattern: `(byte)large_value` or `(ushort)int_value` used as index or size. "
     "SUBPIECE pcode operation in Ghidra flags explicit truncation — extractable."),

    ("193", "Off-by-one Error",
     "B", "TYPE",
     "Loop condition < vs <=, or size allocated is count vs count+1 (null terminator). "
     "Pattern in pseudocode: loop bound `iVar < len` then access `arr[iVar]` — "
     "if len == sizeof(arr), the <= case would overflow. loop_count from func_info "
     "tells us loops exist; detecting the off-by-one requires reading the condition."),

    ("481", "Assigning instead of Comparing",
     "B", "TYPE",
     "= where == was intended. In pseudocode, assignment in conditional: "
     "`if (x = getval())` — Ghidra usually shows this as assignment then branch. "
     "Rare but detectable pattern."),

    # ── CONTROL FLOW ──────────────────────────────────────────────────────────

    ("478", "Missing Default Case in Multiple Condition Expression",
     "B", "FLOW",
     "Switch without default case. Ghidra pseudocode shows switch structure. "
     "If switch has no default and values fall through after the last case, "
     "unhandled values execute subsequent code. Pseudocode-detectable."),

    ("484", "Omitted Break Statement in Switch",
     "B", "FLOW",
     "Fall-through in switch. Visible in pseudocode as consecutive case labels "
     "without return/break between them. Our `switch_count` in func_info counts "
     "switches; detecting fall-through requires reading case structure."),

    ("617", "Reachable Assertion",
     "B", "FLOW",
     "assert() calls that can fire at runtime. Callee detection: __assert_fail, "
     "abort, _wassert. If a function calls abort/assert_fail under a specific "
     "condition, that condition is the assertion. Detectable from callees."),

    ("676", "Use of Potentially Dangerous Function",
     "A", "FLOW",
     "Already handled: our named_callees includes gets, strcpy, sprintf etc. "
     "Could add a DANGEROUS_CALLEE annotation in the calltree output."),

    ("14", "Compiler Removal of Code to Clear Buffers",
     "B", "FLOW",
     "Compiler optimizes away memset() on buffer before free if buffer goes out "
     "of scope (dead store elimination). Can we detect the ABSENCE of a memset "
     "before free? Pattern: buffer allocated, used for sensitive data, freed — "
     "no zero-out between use and free."),

    # ── SYNCHRONIZATION ───────────────────────────────────────────────────────

    ("362", "Race Condition with Shared Resource",
     "B", "SYNC",
     "timing_cv already signals branchy execution. More specific: callee sequence "
     "patterns: EnterCriticalSection/acquire followed by operation followed by "
     "LeaveCriticalSection/release. Gaps in lock coverage (operation outside lock) "
     "require data flow — hard. But PRESENCE of lock patterns is detectable."),

    ("663", "Non-reentrant Function in Concurrent Context",
     "B", "SYNC",
     "Callee detection: strtok, getenv, gmtime, rand, asctime etc. all use global "
     "state, non-reentrant. If function calls these AND is called from multiple "
     "threads (detectable from thread-creation call chains) → potential issue. "
     "Detectable purely from named_callees."),

    # ── INIT / RESOURCE ───────────────────────────────────────────────────────

    ("911", "Improper Update of Reference Count",
     "B", "INIT",
     "Reference counting patterns: inc and dec of a counter field in a struct. "
     "If only one direction is present (increment without decrement or vice versa) "
     "in all observed call paths → potential ref count imbalance. "
     "Memory observer: which field in a struct consistently increments?"),

    ("403", "Exposure of File Descriptor to Unintended Control Sphere",
     "D", "N/A",
     "File descriptor management — too OS-specific and high-level for our current "
     "binary RE focus. Out of scope."),

]


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter", default=None, choices=["A","B","C","D"],
                    help="Show only A (have), B (buildable), C (hard gap), D (out of scope)")
    ap.add_argument("--category", default=None,
                    help="Filter by info structure: MEM CALL TYPE FLOW SYNC INIT")
    opts = ap.parse_args()

    from collections import Counter
    cat_counts = Counter()
    status_counts = Counter()

    header = f"{'CWE':<8} {'ST':2} {'CAT':<12}  TOOLKIT INSPIRATION"
    print(header)
    print("-" * 100)

    for cwe_id, name, status, category, translation in TRANSLATIONS:
        if opts.filter and status != opts.filter:
            continue
        if opts.category and opts.category.upper() not in category:
            continue
        cat_counts[category] += 1
        status_counts[status] += 1
        # Truncate translation for display
        short = translation[:120].replace("\n", " ").replace("  ", " ")
        print(f"CWE-{cwe_id:<6} {status}  {category:<12}  {name}")
        print(f"{'':20}  → {short}")
        print()

    print(f"\nSummary: A={status_counts['A']} (have)  B={status_counts['B']} "
          f"(buildable)  C={status_counts['C']} (hard)  D={status_counts['D']} (skip)")


if __name__ == "__main__":
    main()
