"""
dynamic/probe.py — Path-stratified probe set builder for behavioral fingerprinting.

Parses Ghidra pseudocode to build a probe set that covers every equivalence
partition of the function's input space:

    1. Branch constants  — boundary probes {C-1, C, C+1} at every comparison value
    2. Branch conditions — path-stratification probes (one true-case, one false-case
                           per comparison operator, so each branch arm is exercised)
    3. Baseline          — universal coverage regardless of code content
    4. Powers of two     — shift/scale detection
    5. Derivative pairs  — (x, x^(1<<k), k) for boolean derivative / avalanche analysis

The x%2 false-PRNG problem
--------------------------
Without path stratification, `f(x) = x & 1` looks pseudo-random: consecutive
probes alternate 0/1/0/1.  Extracting the `& 1` condition forces both an even
probe (false-case, result=0) and an odd probe (true-case, result=1) into the set.
The boolean derivative then exposes the function unambiguously:

    D_1 f(x) = f(x) XOR f(x XOR 1) = 1  for all x   ← single-bit selector
    D_2 f(x) = f(x) XOR f(x XOR 2) = 0  for all x

A true PRNG has nonzero D_a for ALL bit positions a — distinguishable at H=1.

CLI
---
    py re_toolkit/dynamic/probe.py --code func.c
    py re_toolkit/dynamic/probe.py --stdin < pseudocode.txt
    py re_toolkit/dynamic/probe.py --code func.c --max-base 128 --deriv-bits 16
"""
from __future__ import annotations
import re, sys, os, json, argparse
from dataclasses import dataclass


# ── data types ────────────────────────────────────────────────────────────────

@dataclass
class ProbePoint:
    value: int
    tag:   str   # why this was chosen: "baseline_zero", "boundary_0x3f_p1", etc.


@dataclass
class ProbeSet:
    """
    Complete structured probe set for one function.

    Attributes
    ----------
    base_probes     list of ProbePoints: boundary + baseline + path-stratified
    deriv_probes    list of (x, x^(1<<k), k): boolean derivative triples
    flat            deduplicated, unsigned-sorted union of all input values
    n_args          estimated argument count from pseudocode signature
    arg_fill        fixed values for args 1..n-1 when varying arg 0
    constants_found dict of {"0xNN": context_snippet} for each extracted constant
    """
    base_probes:     list[ProbePoint]
    deriv_probes:    list[tuple[int, int, int]]
    flat:            list[int]
    n_args:          int
    arg_fill:        list[int]
    constants_found: dict[str, str]

    def summary(self) -> dict:
        return {
            "n_base":    len(self.base_probes),
            "n_deriv":   len(self.deriv_probes),
            "n_flat":    len(self.flat),
            "n_args":    self.n_args,
            "arg_fill":  self.arg_fill,
            "constants": self.constants_found,
        }

    def call_args(self) -> list[list[int]]:
        """Expand flat values into [[v] + arg_fill, ...] for DLLExecutor.call_batch()."""
        return [[v] + self.arg_fill for v in self.flat]


# ── constants ─────────────────────────────────────────────────────────────────

# Universal baseline probes regardless of code content
_BASELINE: list[tuple[int, str]] = [
    (0,                     "baseline_zero"),
    (1,                     "baseline_one"),
    (-1,                    "baseline_neg1"),
    (2,                     "baseline_two"),
    (3,                     "baseline_three"),
    (7,                     "baseline_seven"),
    (127,                   "baseline_i8max"),
    (128,                   "baseline_0x80"),
    (255,                   "baseline_0xff"),
    (256,                   "baseline_0x100"),
    (0x3f,                  "baseline_0x3f"),
    (0x7f,                  "baseline_0x7f"),
    (0x7fff,                "baseline_i16max"),
    (0x8000,                "baseline_i16min"),
    (0xffff,                "baseline_u16max"),
    (0x10000,               "baseline_2pow16"),
    (0x7fffffff,            "baseline_i32max"),
    (0x80000000,            "baseline_i32min"),
    (0xffffffff,            "baseline_u32max"),
    (0x100000000,           "baseline_2pow32"),
    (0x7fffffffffffffff,    "baseline_i64max"),
]

# Operator → (true_offset_from_C, false_offset_from_C)
# true_v = C + true_offset satisfies the condition; false_v = C + false_offset violates it
_OP_CASES: dict[str, tuple[int, int]] = {
    "==":  ( 0,  1),   # == C: C satisfies, C+1 violates
    "!=":  ( 1,  0),   # != C: C+1 satisfies, C violates
    "<":   (-1,  0),   # < C: C-1 satisfies, C violates
    "<=":  ( 0,  1),   # <= C: C satisfies, C+1 violates
    ">":   ( 1,  0),   # > C: C+1 satisfies, C violates
    ">=":  ( 0, -1),   # >= C: C satisfies, C-1 violates
}

# Maximum constant value to emit boundary probes for; skip likely VA-sized values
_MAX_CONST: int = (1 << 32) - 1

# Default bit positions for boolean derivative pairs
_DEFAULT_DERIV_BITS: list[int] = list(range(8))   # bits 0-7


# ── builder ───────────────────────────────────────────────────────────────────

class ProbeBuilder:
    """
    Build a path-stratified ProbeSet from Ghidra pseudocode.

    Parameters
    ----------
    pseudocode : str
        Decompiled pseudocode for the target function (the 'pseudocode' field
        from the calltree JSON, or the full body string).
    max_base : int
        Maximum base probe points before derivative expansion (default 64).
    deriv_bits : list[int] or None
        Bit positions k for boolean derivative pairs (x, x^(1<<k), k).
        None → bits 0-7.  Pass list(range(16)) for wider analysis.
    """

    def __init__(
        self,
        pseudocode: str,
        max_base:   int = 64,
        deriv_bits: list[int] | None = None,
    ):
        self._code       = pseudocode
        self._max_base   = max_base
        self._deriv_bits = deriv_bits if deriv_bits is not None else _DEFAULT_DERIV_BITS

    # ── public ────────────────────────────────────────────────────────────────

    def build(self) -> ProbeSet:
        n_args   = self._count_args()
        arg_fill = [0] * max(0, n_args - 1)

        constants, ctx_map = self._extract_constants()
        branches           = self._extract_branches(constants)

        seen: dict[int, ProbePoint] = {}

        def add(v: int, tag: str) -> None:
            if v not in seen:
                seen[v] = ProbePoint(v, tag)

        # Step 1 — Baseline
        for v, tag in _BASELINE:
            add(v, tag)

        # Step 2 — Boundary probes around each extracted constant
        for c in sorted(constants):
            src = f"0x{c:x}"
            add(c - 1, f"boundary_{src}_m1")
            add(c,     f"boundary_{src}")
            add(c + 1, f"boundary_{src}_p1")

        # Step 3 — Path-stratification: true-case + false-case per branch condition
        for op, threshold, true_v, false_v in branches:
            add(true_v,  f"stratify_{op}_{threshold:#x}_true")
            add(false_v, f"stratify_{op}_{threshold:#x}_false")

        # Step 4 — Powers of two (shift / scale detection, stride detection)
        for k in range(17):
            add(1 << k, f"pow2_{k}")

        # Trim to max_base
        base_probes = list(seen.values())[: self._max_base]
        base_vals   = [p.value for p in base_probes]

        # Step 5 — Boolean derivative pairs
        deriv_probes: list[tuple[int, int, int]] = []
        deriv_extra:  set[int] = set()
        for x in base_vals:
            for k in self._deriv_bits:
                x_flip = x ^ (1 << k)
                deriv_probes.append((x, x_flip, k))
                deriv_extra.add(x_flip)

        # Flat deduplicated list, sorted unsigned
        all_vals = set(base_vals) | deriv_extra
        flat     = sorted(all_vals, key=lambda v: v & 0xFFFFFFFFFFFFFFFF)

        constants_found = {f"0x{c:x}": ctx_map.get(c, "") for c in sorted(constants)}

        return ProbeSet(
            base_probes=base_probes,
            deriv_probes=deriv_probes,
            flat=flat,
            n_args=n_args,
            arg_fill=arg_fill,
            constants_found=constants_found,
        )

    # ── extraction ────────────────────────────────────────────────────────────

    def _count_args(self) -> int:
        """Parse the function signature line to estimate argument count."""
        for line in self._code.splitlines():
            line = line.strip()
            if '(' not in line or ')' not in line:
                continue
            inner = line[line.index('(') + 1 : line.rindex(')')]
            if not inner.strip() or inner.strip().lower() == 'void':
                return 0
            depth = commas = 0
            for ch in inner:
                if ch == '(':   depth += 1
                elif ch == ')': depth -= 1
                elif ch == ',' and depth == 0:
                    commas += 1
            return commas + 1
        return 1

    def _extract_constants(self) -> tuple[set[int], dict[int, str]]:
        """
        Extract integer literals from pseudocode.

        Returns (set_of_values, value→context_snippet).
        Skips values > _MAX_CONST (likely VAs) and values <= 1 (in baseline).
        """
        constants: set[int]       = set()
        ctx_map:   dict[int, str] = {}

        # Hex literals: 0x[0-9a-fA-F]+
        for m in re.finditer(r'0[xX]([0-9a-fA-F]+)', self._code):
            try:
                v = int(m.group(1), 16)
            except ValueError:
                continue
            if 1 < v <= _MAX_CONST:
                constants.add(v)
                ctx_map[v] = m.group(0)

        # Decimal literals: standalone integers not embedded in identifiers
        # (?<![_\w]) prevents matching digits inside FUN_180001234 or param_1
        for m in re.finditer(r'(?<![_\w])(\d+)(?![_\w])', self._code):
            try:
                v = int(m.group(1))
            except ValueError:
                continue
            if 1 < v <= _MAX_CONST:
                constants.add(v)
                ctx_map.setdefault(v, m.group(0))

        return constants, ctx_map

    def _extract_branches(
        self, constants: set[int]
    ) -> list[tuple[str, int, int, int]]:
        """
        Extract (operator, threshold, true_value, false_value) tuples from
        comparison expressions found in the pseudocode.

        For each extracted branch condition, true_value satisfies the condition
        and false_value violates it, enabling path-stratified probing.
        """
        results:    list[tuple[str, int, int, int]] = []
        seen_pairs: set[tuple[str, int]] = set()

        # Comparison operators with RHS constant
        # Negative lookbehind prevents matching >>=, <<=, !=, ==, <=, >= twice
        cmp_re = re.compile(
            r'(?<![<>!=])([<>]=?|[!=]=)'
            r'\s*(0[xX][0-9a-fA-F]+|\d+)'
        )
        for m in cmp_re.finditer(self._code):
            op  = m.group(1)
            raw = m.group(2)
            if op not in _OP_CASES:
                continue
            try:
                c = int(raw, 16) if raw.lower().startswith('0x') else int(raw)
            except ValueError:
                continue
            if c < 0 or c > _MAX_CONST:
                continue
            key = (op, c)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)

            td, fd   = _OP_CASES[op]
            true_v   = max(0, c + td)
            false_v  = max(0, c + fd)
            results.append((op, c, true_v, false_v))

        # Bitmask boolean tests: & MASK used as a boolean condition
        # True case: lowest set bit of mask (minimal value that triggers the branch)
        # False case: 0 (no bits of mask set)
        mask_re = re.compile(r'&\s*(0[xX][0-9a-fA-F]+|\b\d+\b)')
        for m in mask_re.finditer(self._code):
            raw = m.group(1)
            try:
                c = int(raw, 16) if raw.lower().startswith('0x') else int(raw)
            except ValueError:
                continue
            if c <= 0 or c > _MAX_CONST:
                continue
            key = ("&", c)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            lowest_bit = c & (-c)          # isolate lowest set bit of mask
            results.append(("&", c, lowest_bit, 0))

        return results


# ── helpers ───────────────────────────────────────────────────────────────────

def from_pseudocode(pseudocode: str, **kwargs) -> ProbeSet:
    """Convenience wrapper: build a ProbeSet from a pseudocode string."""
    return ProbeBuilder(pseudocode, **kwargs).build()


def default_probe_set(n_args: int = 1) -> ProbeSet:
    """
    Produce a generic ProbeSet without any pseudocode to parse.
    Used when pseudocode is unavailable (e.g., export-only fallback).
    """
    dummy = "undefined8 FUN_00000000(" + ", ".join(f"longlong p{i}" for i in range(n_args)) + ") {}"
    return ProbeBuilder(dummy).build()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Build a path-stratified probe set from Ghidra pseudocode.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--code",       help="Path to pseudocode file (.c / .txt)")
    ap.add_argument("--stdin",      action="store_true", help="Read pseudocode from stdin")
    ap.add_argument("--max-base",   type=int, default=64,
                    help="Max base probe count before derivative expansion (default 64)")
    ap.add_argument("--deriv-bits", type=int, default=8,
                    help="Number of bit positions for derivative pairs (default 8, i.e. bits 0-7)")
    ap.add_argument("--full",       action="store_true",
                    help="Print full flat probe list instead of first 32")
    opts = ap.parse_args()

    if opts.stdin:
        code = sys.stdin.read()
    elif opts.code:
        with open(opts.code, 'r', encoding='utf-8', errors='replace') as f:
            code = f.read()
    else:
        ap.error("provide --code or --stdin")

    pb = ProbeBuilder(code, max_base=opts.max_base, deriv_bits=list(range(opts.deriv_bits)))
    ps = pb.build()

    print(json.dumps(ps.summary(), indent=2))

    limit = None if opts.full else 32
    flat_display = ps.flat[:limit]
    print(f"\n# flat probe set preview ({len(ps.flat)} total unique values):")
    print(json.dumps([hex(v) for v in flat_display], indent=2))
    if limit and len(ps.flat) > limit:
        print(f"  ... ({len(ps.flat) - limit} more, use --full to see all)")
