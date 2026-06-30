"""
dynamic/fingerprint.py — Behavioral metrics engine.

Takes DLLExecutor.call_batch() results + the ProbeSet from probe.py and
computes a structured FingerprintMetrics that covers the full diagnostic space:

  avalanche      — boolean derivative / Strict Avalanche Criterion; key for
                   distinguishing hash/PRNG (≈0.5) from linear/structured (0 or 1)
  entropy        — Shannon entropy of output distribution; 1.0 = uniform (hash/PRNG)
  bijectivity    — unique_outputs / unique_inputs; ~1.0 = injective (good PRNG)
  xor_linearity  — fraction of input-bit flips where D_k f is constant across x;
                   ~1.0 = XOR cipher; ~0 = nonlinear hash
  monotonicity   — fraction of sorted-input pairs where output non-decreases;
                   ~1.0 = arithmetic / codec; ~0.5 = random
  first_diff_cv  — coefficient of variation of |f(x+1)−f(x)|; ≈0 = linear,
                   high = hash-like
  period_2/3     — fraction of probes satisfying f(x) == f(x+P); >0.9 = periodic
  is_boolean     — all outputs in {0, 1}; indicates bit-selection or classifier
  is_constant    — all outputs identical; degenerate / always-return function

These metrics, combined by classify.py, collapse FUNCTION_IDENTIFICATION_STRIPPED
from H=2 toward H=1 for the ~35-40% numeric/crypto function class.

References
----------
  Software Ethology (Xu et al. 2019) — behavioral fingerprinting via I/O vectors
  Strict Avalanche Criterion — NIST definition for cryptographic hash quality
  Walsh-Hadamard Transform — spectral identification of boolean function nonlinearity

CLI
---
    cat results.json | py re_toolkit/dynamic/fingerprint.py
    py re_toolkit/dynamic/fingerprint.py --results results.json --deriv-pairs deriv.json
"""
from __future__ import annotations
import math, json, sys, os, argparse
from dataclasses import dataclass, asdict
from collections import Counter
from typing import Optional

# ── imports (works both as package member and standalone script) ──────────────
try:
    from .execute import ExecuteResult
    from .probe   import ProbeSet
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from execute import ExecuteResult  # type: ignore
    from probe   import ProbeSet       # type: ignore


# ── constants (empirical thresholds imported from constants.py) ───────────────

try:
    from .constants import (
        FINGERPRINT_BITS as _BITS, WHT_BITS as _WHT_BITS,
        SYNOPSIS_HIGH_AVALANCHE, SYNOPSIS_NO_AVALANCHE,
        SYNOPSIS_HIGH_ENTROPY, SYNOPSIS_LOW_ENTROPY,
        SYNOPSIS_BIJECTIVE, SYNOPSIS_LINEAR_THRESHOLD,
        SYNOPSIS_LINEAR_DELTA_CV, SYNOPSIS_GUARD_SENTINEL,
        SYNOPSIS_BRANCHY_TIMING, SYNOPSIS_FLAT_TIMING,
    )
except ImportError:
    from constants import (                                             # type: ignore
        FINGERPRINT_BITS as _BITS, WHT_BITS as _WHT_BITS,
        SYNOPSIS_HIGH_AVALANCHE, SYNOPSIS_NO_AVALANCHE,
        SYNOPSIS_HIGH_ENTROPY, SYNOPSIS_LOW_ENTROPY,
        SYNOPSIS_BIJECTIVE, SYNOPSIS_LINEAR_THRESHOLD,
        SYNOPSIS_LINEAR_DELTA_CV, SYNOPSIS_GUARD_SENTINEL,
        SYNOPSIS_BRANCHY_TIMING, SYNOPSIS_FLAT_TIMING,
    )

_MASK64 = 0xFFFFFFFFFFFFFFFF


# ── result type ───────────────────────────────────────────────────────────────

@dataclass
class FingerprintMetrics:
    """
    All behavioral metrics for one function, derived from probe I/O pairs.

    scalar metrics are floats in [0, 1] unless otherwise noted.
    """
    # ── provenance ────────────────────────────────────────────────────────────
    func_id:         str    # from ExecuteResult.func_id
    n_samples:       int    # total probes attempted
    n_errors:        int    # probes that returned an error

    # ── avalanche (boolean derivative) ───────────────────────────────────────
    avalanche_mean:     float        # avg frac output bits flipped per input bit flip
    avalanche_by_bit:   list[float]  # per-input-bit-position (index = bit k)
    deriv_const_frac:   float        # fraction of input bits whose D_k f(x) is constant
                                     # across all x; 1.0 = XOR-linear, 0.0 = nonlinear hash

    # ── output distribution ───────────────────────────────────────────────────
    entropy_norm:     float   # Shannon entropy / log2(n_unique_in); 1.0 = uniform
    n_unique_out:     int
    n_unique_in:      int
    bijectivity:      float   # n_unique_out / n_unique_in
    output_min:       int
    output_max:       int

    # ── linearity ─────────────────────────────────────────────────────────────
    xor_linear_frac:  float   # same as deriv_const_frac; alias for classifier clarity
    add_linear_frac:  float   # frac (x,y) pairs: f(x+y)==f(x)+f(y) mod 2^64

    # ── algebraic degree (ANF / Möbius transform over GF(2)) ─────────────────
    algebraic_degree: int     # degree of f's LSB over low-5-bit input space via ANF transform
                              # -1 = insufficient coverage (<16 inputs in [0,32))
                              #  0 = constant   1 = XOR-linear (CRC/cipher/LFSR)
                              #  2 = quadratic  ≥4 = hash-like nonlinearity

    # ── monotonicity ──────────────────────────────────────────────────────────
    monotone_inc_frac: float  # frac sorted-input pairs where output non-decreases
    monotone_dec_frac: float  # frac where output non-increases

    # ── finite differences ────────────────────────────────────────────────────
    first_diff_mean:  float   # mean |f(x+1)−f(x)| over consecutive probes
    first_diff_cv:    float   # coefficient of variation; ≈0 = linear, high = hash

    # ── periodicity ──────────────────────────────────────────────────────────
    period_2_frac:    float   # frac probes satisfying f(x) == f(x+2)
    period_3_frac:    float   # frac probes satisfying f(x) == f(x+3)

    # ── guard / early-exit detection ─────────────────────────────────────────
    sentinel_frac:    float   # fraction of probes returning the single most-common output;
                              # high (>0.3) = likely early-exit guard or step-function;
                              # near-zero = hash/PRNG (no dominant output value)
    sentinel_value:   int     # the most-common output value itself

    # ── timing (call-graph shape proxy) ──────────────────────────────────────
    timing_cv:        float   # coefficient of variation of elapsed_us across probes
                              # low (~0) = flat call graph (hash/PRNG/arithmetic)
                              # high (>0.5) = input-dependent branching (domain function, FSM)

    # ── derived flags ─────────────────────────────────────────────────────────
    is_boolean:       bool    # all outputs in {0, 1}
    is_constant:      bool    # all outputs identical
    is_near_identity: bool    # mean |f(x)−x| / mean |x| < 0.01

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def synopsis(self) -> str:
        """One-line summary for LLM hint injection."""
        flags = []
        if self.is_constant:       flags.append("CONSTANT")
        if self.is_boolean:        flags.append("BOOLEAN")
        if self.is_near_identity:  flags.append("NEAR_IDENTITY")
        if self.avalanche_mean > SYNOPSIS_HIGH_AVALANCHE:    flags.append("HIGH_AVALANCHE")
        elif self.avalanche_mean < SYNOPSIS_NO_AVALANCHE:    flags.append("NO_AVALANCHE")
        if self.entropy_norm > SYNOPSIS_HIGH_ENTROPY:        flags.append("HIGH_ENTROPY")
        elif self.entropy_norm < SYNOPSIS_LOW_ENTROPY:       flags.append("LOW_ENTROPY")
        if self.bijectivity > SYNOPSIS_BIJECTIVE:            flags.append("BIJECTIVE")
        if self.xor_linear_frac > SYNOPSIS_LINEAR_THRESHOLD:  flags.append("XOR_LINEAR")
        if self.add_linear_frac > SYNOPSIS_LINEAR_THRESHOLD:  flags.append("ADD_LINEAR")
        if self.monotone_inc_frac > SYNOPSIS_LINEAR_THRESHOLD: flags.append("MONOTONE_INC")
        if self.monotone_dec_frac > SYNOPSIS_LINEAR_THRESHOLD: flags.append("MONOTONE_DEC")
        if self.first_diff_cv < SYNOPSIS_LINEAR_DELTA_CV:    flags.append("LINEAR_DELTA")
        if self.period_2_frac > SYNOPSIS_LINEAR_THRESHOLD:   flags.append("PERIOD_2")
        if self.period_3_frac > SYNOPSIS_LINEAR_THRESHOLD:   flags.append("PERIOD_3")
        if self.sentinel_frac > SYNOPSIS_GUARD_SENTINEL:     flags.append(f"GUARD_SENTINEL({self.sentinel_value:#x})")
        if self.timing_cv > SYNOPSIS_BRANCHY_TIMING:         flags.append("BRANCHY_TIMING")
        elif self.timing_cv < SYNOPSIS_FLAT_TIMING:          flags.append("FLAT_TIMING")
        if self.algebraic_degree == -1:   flags.append("ALG_DEG_UNKNOWN(insufficient_low_inputs)")
        elif self.algebraic_degree == 0:  flags.append("ALG_DEG_CONST")
        elif self.algebraic_degree == 1:  flags.append("ALG_DEG_LINEAR")
        elif self.algebraic_degree == 2:  flags.append("ALG_DEG_QUADRATIC")
        elif self.algebraic_degree >= 4:  flags.append("ALG_DEG_HIGH")
        flag_str = " ".join(flags) if flags else "UNCLASSIFIED"
        return (
            f"{self.func_id}  [{flag_str}]  "
            f"avalanche={self.avalanche_mean:.3f}  "
            f"entropy={self.entropy_norm:.3f}  "
            f"bijective={self.bijectivity:.3f}  "
            f"monotone_inc={self.monotone_inc_frac:.3f}  "
            f"deriv_const={self.deriv_const_frac:.3f}  "
            f"alg_deg={self.algebraic_degree}"
        )


# ── helpers ───────────────────────────────────────────────────────────────────

def _popcount64(x: int) -> int:
    return bin(x & _MASK64).count('1')


def _entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    n      = len(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


def _cv(values: list[float]) -> float:
    """Coefficient of variation; 0 if mean is 0."""
    if len(values) < 2:
        return 0.0
    mu = sum(values) / len(values)
    if mu == 0.0:
        return 0.0
    var  = sum((v - mu) ** 2 for v in values) / len(values)
    return math.sqrt(var) / abs(mu)


def _period_frac(io: dict[int, int], period: int) -> float:
    """Fraction of probes x where f(x) == f(x + period) (both in io)."""
    total = matches = 0
    for x, fx in io.items():
        xp = x + period
        if xp in io:
            total += 1
            if io[xp] == fx:
                matches += 1
    return matches / max(1, total)


# _WHT_BITS imported from constants.py above

def wht_spectral_degree(io: dict[int, int], wbits: int = _WHT_BITS) -> int:
    """
    Algebraic degree of f over the low-wbits input space, computed via the
    Möbius (ANF) transform over GF(2).

    Checks each output bit position 0 .. wbits-1 independently and returns
    the MAXIMUM degree found.  Bit 0 alone is always degree ≤ 1 for modular-
    arithmetic functions (carry from x*C at bit0 is still linear); the
    nonlinearity from carry propagation first appears at bit 2+.

    Returns -1 if fewer than 2^(wbits-1) inputs in [0, 2^wbits) are in io.

    Interpretation:
      0  constant (degenerate)
      1  XOR-linear: CRC, stream cipher, LFSR, shifts+XOR — all output bits linear
      2  carry-nonlinear: modular multiplication introduces quadratic carry terms
      ≥4  hash-like: MurmurHash / FNV finalizer stages typically reach 4-5 over wbits=5
      -1  insufficient probe coverage
    """
    n = 1 << wbits
    if sum(1 for x in range(n) if x in io) < n // 2:
        return -1

    def _anf_degree(bit_pos: int) -> int:
        table = [(io.get(x, 0) >> bit_pos) & 1 for x in range(n)]
        h = 1
        while h < n:
            for i in range(0, n, h * 2):
                for j in range(i, i + h):
                    table[j + h] ^= table[j]
            h *= 2
        return max((bin(s).count('1') for s in range(n) if table[s]), default=0)

    return max(_anf_degree(k) for k in range(wbits))


# ── main entry point ──────────────────────────────────────────────────────────

def compute(
    results:   list[ExecuteResult],
    probe_set: ProbeSet,
    bits:      int = _BITS,
) -> FingerprintMetrics:
    """
    Compute all behavioral metrics from call_batch results.

    Parameters
    ----------
    results   : list returned by DLLExecutor.call_batch() — must be in the same
                order as probe_set.call_args()
    probe_set : ProbeSet from ProbeBuilder.build()
    bits      : assumed output bit width for avalanche calculation (default 64)
    """
    func_id   = results[0].func_id if results else "unknown"
    n_samples = len(results)
    n_errors  = sum(1 for r in results if r.error is not None)

    # ── build primary I/O map: arg[0] → retval ───────────────────────────────
    # Signed interpretation: retval from ctypes c_int64 is already signed.
    # We keep signed values for arithmetic metrics, mask to unsigned for XOR/bit ops.
    io: dict[int, int] = {}
    for r in results:
        if r.retval is not None and r.args:
            x = r.args[0]
            if x not in io:
                io[x] = r.retval

    if not io:
        # All probes errored — return a zero metrics object
        return _zero_metrics(func_id, n_samples, n_errors)

    outputs = list(io.values())

    # ── avalanche (boolean derivative) ───────────────────────────────────────
    # For each (x, x_flip, k) in deriv_probes: compute D_k f(x) = f(x) XOR f(x_flip).
    # avalanche_by_bit[k] = mean fraction of output bits that flipped when bit k was flipped.
    # deriv_const_frac: for each bit k, check if D_k f(x) is constant across all x.

    bit_sums:    dict[int, list[float]] = {}   # k → [frac_bits_flipped per x]
    bit_derivs:  dict[int, list[int]]   = {}   # k → [D_k f(x) values] for const-check

    for x, x_flip, k in probe_set.deriv_probes:
        fx      = io.get(x)
        fx_flip = io.get(x_flip)
        if fx is None or fx_flip is None:
            continue
        d = (fx ^ fx_flip) & _MASK64
        frac = _popcount64(d) / bits
        bit_sums.setdefault(k, []).append(frac)
        bit_derivs.setdefault(k, []).append(d)

    all_bits = sorted(bit_sums.keys())
    avalanche_by_bit = [
        sum(bit_sums[k]) / len(bit_sums[k]) if bit_sums.get(k) else 0.0
        for k in all_bits
    ]
    avalanche_mean = sum(avalanche_by_bit) / len(avalanche_by_bit) if avalanche_by_bit else 0.0

    # deriv_const_frac: fraction of bit positions where D_k f(x) is identical for all x
    const_bits = 0
    for k, derivs in bit_derivs.items():
        if len(set(derivs)) == 1:   # D_k f is constant across all probed x
            const_bits += 1
    deriv_const_frac = const_bits / max(1, len(bit_derivs))

    # ── output distribution ───────────────────────────────────────────────────
    n_unique_in  = len(io)
    n_unique_out = len(set(outputs))
    bijectivity  = n_unique_out / max(1, n_unique_in)

    # Entropy normalised to [0,1]: divide by log2(n_unique_in) so 1.0 = fully uniform
    raw_entropy  = _entropy(outputs)
    max_entropy  = math.log2(n_unique_in) if n_unique_in > 1 else 1.0
    entropy_norm = min(1.0, raw_entropy / max_entropy)

    output_min = min(outputs)
    output_max = max(outputs)

    # ── XOR-linearity (same signal as deriv_const_frac for the LLM) ──────────
    xor_linear_frac = deriv_const_frac

    # ── additive linearity: f(x+y) mod 2^64 == f(x)+f(y) mod 2^64 ───────────
    keys = list(io.keys())
    add_pairs = [(keys[i], keys[j]) for i in range(min(20, len(keys)))
                                    for j in range(i+1, min(20, len(keys)))]
    add_linear_matches = 0
    add_linear_total   = 0
    for x, y in add_pairs:
        xy = (x + y) & _MASK64
        if xy in io:
            add_linear_total += 1
            expected = (io[x] + io[y]) & _MASK64
            if io[xy] & _MASK64 == expected:
                add_linear_matches += 1
    add_linear_frac = add_linear_matches / max(1, add_linear_total)

    # ── monotonicity (sorted by input) ───────────────────────────────────────
    sorted_io = sorted(io.items())   # sorted by input key (unsigned interpretation)
    inc = dec = total_consec = 0
    for i in range(len(sorted_io) - 1):
        x0, f0 = sorted_io[i]
        x1, f1 = sorted_io[i + 1]
        total_consec += 1
        if f1 >= f0:  inc += 1
        if f1 <= f0:  dec += 1
    monotone_inc_frac = inc / max(1, total_consec)
    monotone_dec_frac = dec / max(1, total_consec)

    # ── finite differences (over sorted consecutive inputs with step 1) ───────
    # Only use pairs where x+1 is also in io (actual consecutive integer pairs)
    diffs: list[float] = []
    for x, fx in io.items():
        if x + 1 in io:
            diffs.append(abs(io[x + 1] - fx))
    first_diff_mean = sum(diffs) / len(diffs) if diffs else 0.0
    first_diff_cv   = _cv(diffs)

    # ── periodicity ──────────────────────────────────────────────────────────
    period_2_frac = _period_frac(io, 2)
    period_3_frac = _period_frac(io, 3)

    # ── algebraic degree (ANF / Möbius transform) ────────────────────────────
    algebraic_degree = wht_spectral_degree(io)

    # ── guard / early-exit detection ─────────────────────────────────────────
    # If a guard fires for many inputs (bounds check, null check, size check),
    # a sentinel value (-1, 0, unchanged) dominates the output distribution.
    # sentinel_frac = fraction of probes returning the single most-common output.
    # Hash/PRNG: near 0. Guarded functions: >0.3.  Step-functions: near 1.0.
    output_counts  = Counter(outputs)
    sentinel_value = output_counts.most_common(1)[0][0] if output_counts else 0
    sentinel_frac  = output_counts[sentinel_value] / max(1, len(outputs))

    # ── timing (call-graph shape proxy) ──────────────────────────────────────
    # CV of elapsed_us across all non-error probes.
    # Flat call graphs (hash/PRNG): near-constant timing → low CV.
    # Domain functions (switch on constants, FSMs): input-dependent branching → high CV.
    # Soft signal only — ctypes call overhead dominates for very fast functions.
    timings   = [r.elapsed_us for r in results if r.error is None and r.elapsed_us > 0]
    timing_cv = _cv(timings)

    # ── derived flags ─────────────────────────────────────────────────────────
    is_boolean      = all(v in (0, 1) for v in outputs)
    is_constant     = len(set(outputs)) == 1
    # near-identity: |f(x) - x| / |x| < 1% on average (skip x=0)
    identity_errs = [abs(fx - x) / max(1, abs(x)) for x, fx in io.items() if x != 0]
    is_near_identity = bool(identity_errs and
                            sum(identity_errs) / len(identity_errs) < 0.01)

    return FingerprintMetrics(
        func_id=func_id,
        n_samples=n_samples,
        n_errors=n_errors,
        avalanche_mean=round(avalanche_mean, 4),
        avalanche_by_bit=[round(v, 4) for v in avalanche_by_bit],
        deriv_const_frac=round(deriv_const_frac, 4),
        entropy_norm=round(entropy_norm, 4),
        n_unique_out=n_unique_out,
        n_unique_in=n_unique_in,
        bijectivity=round(bijectivity, 4),
        output_min=output_min,
        output_max=output_max,
        xor_linear_frac=round(xor_linear_frac, 4),
        add_linear_frac=round(add_linear_frac, 4),
        algebraic_degree=algebraic_degree,
        monotone_inc_frac=round(monotone_inc_frac, 4),
        monotone_dec_frac=round(monotone_dec_frac, 4),
        first_diff_mean=round(first_diff_mean, 2),
        first_diff_cv=round(first_diff_cv, 4),
        period_2_frac=round(period_2_frac, 4),
        period_3_frac=round(period_3_frac, 4),
        sentinel_frac=round(sentinel_frac, 4),
        sentinel_value=sentinel_value,
        timing_cv=round(timing_cv, 4),
        is_boolean=is_boolean,
        is_constant=is_constant,
        is_near_identity=is_near_identity,
    )


def _zero_metrics(func_id: str, n_samples: int, n_errors: int) -> FingerprintMetrics:
    return FingerprintMetrics(
        func_id=func_id, n_samples=n_samples, n_errors=n_errors,
        avalanche_mean=0.0, avalanche_by_bit=[], deriv_const_frac=0.0,
        entropy_norm=0.0, n_unique_out=0, n_unique_in=0, bijectivity=0.0,
        output_min=0, output_max=0, xor_linear_frac=0.0, add_linear_frac=0.0,
        algebraic_degree=-1,
        monotone_inc_frac=0.0, monotone_dec_frac=0.0,
        first_diff_mean=0.0, first_diff_cv=0.0,
        period_2_frac=0.0, period_3_frac=0.0,
        sentinel_frac=0.0, sentinel_value=0,
        timing_cv=0.0,
        is_boolean=False, is_constant=False, is_near_identity=False,
    )


# ── Self-test ─────────────────────────────────────────────────────────────────

def _verify():
    """Sanity-check fingerprint metrics on synthetic probe results."""
    from dynamic.execute import ExecuteResult  # type: ignore

    def _r(x, y): return ExecuteResult("TEST", [x], y, None, 0.1, 0)

    try:
        from dynamic.probe import default_probe_set
    except ImportError:
        from probe import default_probe_set  # type: ignore

    ps = default_probe_set(n_args=1)

    # POSITIVE: identity function f(x)=x → is_near_identity=True
    results = [_r(x, x) for x in ps.flat]
    m = compute(results, ps)
    assert m.is_near_identity, f"identity: expected is_near_identity, got {m.synopsis()}"

    # POSITIVE: constant function f(x)=42 → is_constant=True
    results = [_r(x, 42) for x in ps.flat]
    m = compute(results, ps)
    assert m.is_constant, f"constant: expected is_constant, got {m.synopsis()}"

    # POSITIVE: XOR function f(x) = x ^ 0xDEAD → xor_linear_frac ≈ 1.0
    results = [_r(x, x ^ 0xDEAD) for x in ps.flat]
    m = compute(results, ps)
    assert m.xor_linear_frac > 0.80, f"XOR: expected xor_linear > 0.80, got {m.xor_linear_frac:.3f}"

    # POSITIVE: synopsis flags include XOR_LINEAR
    assert "XOR_LINEAR" in m.synopsis(), f"synopsis missing XOR_LINEAR: {m.synopsis()}"

    print("OK: fingerprint.py _verify() passed")
    print(f"  identity/constant/XOR cases confirmed")
    print(f"  SYNOPSIS_* constants imported from constants.py")


# ── convenience wrapper ───────────────────────────────────────────────────────

def run(
    executor,
    func: int | str,
    pseudocode: str = "",
    n_args:     int = 1,
    bits:       int = _BITS,
) -> FingerprintMetrics:
    """
    One-call convenience: build probe set → call_batch → compute metrics.

    Parameters
    ----------
    executor    : DLLExecutor instance
    func        : Ghidra VA (int) or export name (str)
    pseudocode  : Ghidra pseudocode string (used for path-stratified probing)
    n_args      : fallback arg count if pseudocode is empty
    bits        : assumed output bit width (default 64)
    """
    try:
        from .probe import ProbeBuilder, default_probe_set
    except ImportError:
        from probe import ProbeBuilder, default_probe_set  # type: ignore

    ps = ProbeBuilder(pseudocode).build() if pseudocode else default_probe_set(n_args)
    results = executor.call_batch(func, ps.call_args())
    return compute(results, ps, bits=bits)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Compute fingerprint metrics from call_batch JSON results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--dll",      help="DLL path — if given, run probe+execute+fingerprint in one step")
    ap.add_argument("--func",     help="Export name or Ghidra VA (0x...) — requires --dll")
    ap.add_argument("--code",     help="Pseudocode file for path-stratified probing")
    ap.add_argument("--n-args",   type=int, default=1, help="Arg count if no pseudocode (default 1)")
    ap.add_argument("--bits",     type=int, default=64, help="Output bit width (default 64)")
    ap.add_argument("--synopsis", action="store_true", help="Print one-line synopsis instead of full JSON")
    opts = ap.parse_args()

    if opts.dll and opts.func:
        # Full pipeline mode
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        try:
            from dynamic.execute import DLLExecutor
            from dynamic.probe   import ProbeBuilder, default_probe_set
        except ImportError:
            from execute import DLLExecutor  # type: ignore
            from probe   import ProbeBuilder, default_probe_set  # type: ignore

        code = ""
        if opts.code:
            with open(opts.code, 'r', encoding='utf-8', errors='replace') as f:
                code = f.read()

        ex = DLLExecutor(opts.dll)
        func_spec = int(opts.func, 16) if opts.func.startswith("0x") else opts.func
        ps        = ProbeBuilder(code).build() if code else default_probe_set(opts.n_args)
        results   = ex.call_batch(func_spec, ps.call_args())
        metrics   = compute(results, ps, bits=opts.bits)

    else:
        ap.error("provide --dll and --func for full-pipeline mode")

    if opts.synopsis:
        print(metrics.synopsis())
    else:
        print(metrics.to_json())
