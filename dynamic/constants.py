"""
dynamic/constants.py — Single source of truth for all empirically-tuned and
machine-variable thresholds used across the dynamic analysis pipeline.

THREE CATEGORIES
----------------

MACHINE_CALIBRATED — values that vary by CPU speed, OS scheduler, cache size.
    DO NOT hardcode. Run `py -3.13 cli.py calibrate` to measure and store in
    calibration.json. If calibration.json is absent, the defaults here are
    conservative fallbacks — correct but not optimal.

EMPIRICAL — measured on the 111-function test suite (2026-06-19, Windows 11,
    w64devkit gcc stripped DLLs). Stable across machines because they measure
    statistical properties of algorithm outputs, not timing. Change only when
    test suite accuracy drops and you have data justifying the new value.

STRUCTURAL — fixed by the math or architecture. Never change without redesigning
    the metric that uses them.

HOW TO READ PROVENANCE
----------------------
Each constant has:
  basis     — how the value was derived (sweep, theory, literature)
  measured  — date of last measurement, or "theoretical"
  effect    — what breaks if you raise/lower it

TO RECALIBRATE MACHINE-SPECIFIC VALUES:
    py -3.13 cli.py calibrate
This runs micro-benchmarks, writes calibration.json, and prints which
constants changed from their defaults.
"""

import os as _os
import json as _json

_here = _os.path.dirname(_os.path.abspath(__file__))
_CAL_PATH = _os.path.join(_here, "calibration.json")


def _load_calibration() -> dict:
    if _os.path.exists(_CAL_PATH):
        try:
            with open(_CAL_PATH) as f:
                return _json.load(f)
        except Exception:
            pass
    return {}


_cal = _load_calibration()


def _cal_get(key: str, default: float) -> float:
    """Return calibrated value if available, else conservative default."""
    return _cal.get(key, default)


# ── MACHINE_CALIBRATED ────────────────────────────────────────────────────────

# Timing coefficient of variation below which a constant-output function is
# classified "constant" rather than "stateful".
# basis:    genuine `return K;` measures < 0.05 on all tested machines.
#           0.15 confirmed correct on 111-function sweep (2026-06-19, 93.7% acc).
#           Lower bound is OS jitter noise floor × 3 — measure with `calibrate`.
# effect↑:  fast stateful functions misclassified as "constant" (miss)
# effect↓:  true constant functions misclassified as "stateful" (false positive)
STATEFUL_TIMING_CV_THRESHOLD: float = _cal_get("stateful_timing_cv_threshold", 0.15)

# IPSampler: microseconds between thread-suspend polls.
# basis:    Windows thread-switch latency ≈ 10–20 µs on a typical desktop.
#           15 µs gives ~2 samples per thread quantum without saturating the CPU.
# effect↑:  fewer samples, coarser IP histogram
# effect↓:  more samples, but may dominate the function's own execution time
IPSAMPLER_INTERVAL_US: float = _cal_get("ipsampler_interval_us", 15.0)

# IPSampler: total iterations (number of suspend/resume cycles per probe call).
# basis:    600 × 15 µs = 9 ms window. Functions < 1 µs will collect < 10 samples
#           and be skipped (see IPSAMPLER_MIN_SAMPLES).
IPSAMPLER_N_ITERS: int = int(_cal_get("ipsampler_n_iters", 600))

# IPSampler: minimum in-function samples required to emit a pattern.
# basis:    < 10 samples → histogram too sparse to distinguish guard/loop/branchy.
# effect↑:  more fast functions skipped; effect↓: noisier pattern labels
IPSAMPLER_MIN_SAMPLES: int = int(_cal_get("ipsampler_min_samples", 10))


# ── EMPIRICAL — classification rule thresholds ────────────────────────────────
# All measured on 111-function suite, 2026-06-19. Accuracy 93.7%.
# Changing these requires a full sweep re-run to verify accuracy holds.

# I/O match score to claim exact algorithm identification (e.g. "this is xorshift64").
# basis:    score=1.0 means every probe matched the reference implementation.
#           0.90 allows for 10% mismatch from argument aliasing or seeding differences.
# measured: 2026-06-19 (no FP observed above 0.90 in sweep)
EXACT_THRESHOLD: float = 0.90

# I/O match score for "likely" class-level identification.
CLASS_THRESHOLD: float = 0.70

# Fraction of pseudocode constants matching Windows API extension dicts → "domain" hint.
DOMAIN_CONST_FRAC: float = 0.50

# Minimum confidence to emit to knowledge bus (avoids polluting KB with noise).
# basis:    below 0.65, evidence is too weak to be useful across sessions.
KB_EMIT_CONFIDENCE: float = 0.65

# --- cipher rule ---
# basis:    true XOR-linear functions (stream ciphers, LFSR steps) score > 0.95.
#           0.80 accepts functions where some probes alias.
XOR_LINEAR_CIPHER_THRESHOLD: float = 0.80

# --- arith rule ---
MONOTONE_ARITH_THRESHOLD: float = 0.80
ARITH_LINEAR_DELTA_CV: float = 0.10       # first_diff_cv below this → constant delta

# --- prng rule ---
PRNG_AVALANCHE_MIN: float = 0.40
PRNG_BIJECTIVITY_MIN: float = 0.70
PRNG_ENTROPY_MIN: float = 0.70

# --- hash rule ---
HASH_AVALANCHE_MIN: float = 0.35
HASH_ENTROPY_MIN: float = 0.60

# --- checksum rule ---
CHECKSUM_BIJECTIVITY_MAX: float = 0.50
CHECKSUM_ENTROPY_MIN: float = 0.30
CHECKSUM_AVALANCHE_MAX: float = 0.40

# --- guard rule ---
GUARD_SENTINEL_DOMINANT: float = 0.50    # sentinel_frac > this → guard (boolean outputs)
GUARD_SENTINEL_SECONDARY: float = 0.40  # sentinel_frac > this with low avalanche → guard
GUARD_AVALANCHE_MAX: float = 0.30       # avalanche below this confirms guard (not hash)
GUARD_HINT_FRAC: float = 0.20           # sentinel_frac above this → include in llm_hint

# --- domain hint ---
DOMAIN_TIMING_CV_BRANCHY: float = 0.50  # timing_cv > this → "BRANCHY_TIMING" flag
DOMAIN_TIMING_CV_FLAT: float = 0.10     # timing_cv < this → "FLAT_TIMING" flag

# --- unknown rule explanation thresholds (match rule thresholds above) ---
UNKNOWN_AVALANCHE_FLOOR: float = HASH_AVALANCHE_MIN
UNKNOWN_SENTINEL_FLOOR: float = GUARD_SENTINEL_SECONDARY
UNKNOWN_MONOTONE_FLOOR: float = MONOTONE_ARITH_THRESHOLD
UNKNOWN_XOR_FLOOR: float = XOR_LINEAR_CIPHER_THRESHOLD


# ── EMPIRICAL — fingerprint synopsis flags ────────────────────────────────────
# These control the SYNOPSIS string flags (HIGH_AVALANCHE, GUARD_SENTINEL, etc.)
# Used only for display; do not affect classification decisions.

SYNOPSIS_HIGH_AVALANCHE: float = 0.45
SYNOPSIS_NO_AVALANCHE: float = 0.05
SYNOPSIS_HIGH_ENTROPY: float = 0.90
SYNOPSIS_LOW_ENTROPY: float = 0.10
SYNOPSIS_BIJECTIVE: float = 0.95
SYNOPSIS_LINEAR_THRESHOLD: float = 0.90   # XOR_LINEAR, ADD_LINEAR, MONOTONE, PERIOD flags
SYNOPSIS_LINEAR_DELTA_CV: float = 0.05
SYNOPSIS_GUARD_SENTINEL: float = 0.30
SYNOPSIS_BRANCHY_TIMING: float = DOMAIN_TIMING_CV_BRANCHY
SYNOPSIS_FLAT_TIMING: float = DOMAIN_TIMING_CV_FLAT


# ── EMPIRICAL — IP pattern thresholds (runtime_probe IPSampler) ───────────────

# Fraction of in-function samples in the first 20% of the function body
# required to classify as "guard" (early-exit pattern).
IPSAMPLER_GUARD_EARLY_FRAC: float = 0.20   # "first 20% of function"
IPSAMPLER_GUARD_THRESHOLD: float = 0.60    # > 60% there → guard

# Sliding window size and threshold for "loop" pattern.
IPSAMPLER_LOOP_WINDOW: float = 0.10        # 10% of function body
IPSAMPLER_LOOP_THRESHOLD: float = 0.50     # > 50% in any window → loop
IPSAMPLER_LOOP_GUARD_EXCL: float = 0.40   # guard_frac below this to avoid guard/loop conflict

# Threshold per window to count as a "peak" for "branchy" pattern.
IPSAMPLER_BRANCHY_PEAK: float = 0.15       # each peak must hold > 15% of samples
IPSAMPLER_BRANCHY_MIN_PEAKS: int = 2       # at least 2 peaks → branchy

# Tier 3 activation threshold: run IPSampler when discriminant < this.
# basis:    discriminant = max(avalanche_mean, entropy_norm, sentinel_frac) - 0.5
#           < 0.30 means all three metrics are below 0.80 — insufficient signal.
TIER3_DISCRIMINANT_THRESHOLD: float = 0.30

# ContextReplay: number of repeated calls with same context to test purity.
CONTEXT_REPLAY_N_RUNS: int = int(_cal_get("context_replay_n_runs", 12))

# ContextReplay: number of different argument values to test arg-sensitivity.
CONTEXT_REPLAY_N_TEST_ARGS: int = 4

# Sign-extension detection threshold for return-type inference.
# basis:    if > 10% of outputs have 0xFFFFFFFF in high 32 bits, return is int32.
SIGN_EXT_FRAC: float = 0.10


# ── STRUCTURAL — fixed by design ───────────────────────────────────────────────

# Output bit width used for avalanche computation (Hamming distance).
# Change only if adding 32-bit DLL support.
FINGERPRINT_BITS: int = 64

# Walsh-Hadamard Transform window: algebraic degree computed over [0, 2^WHT_BITS).
# 5 → 32 inputs; covers degree up to 5. Degree ≥ 4 → hash-like.
# Increasing costs O(2^N); 6 = 64 inputs is feasible but rarely needed.
WHT_BITS: int = 5

# Knowledge bus stability tier thresholds.
KB_INVARIANT_LAYERS: int = 3    # confirmed by this many independent layers → INVARIANT
KB_INVARIANT_COUNT: int = 5     # OR seen this many times total → INVARIANT
KB_COMMON_LAYERS: int = 2       # confirmed by this many layers → COMMON
KB_COMMON_COUNT: int = 3        # OR seen this many times → COMMON

# PE guard-page size for call_buffer overflow detection.
GUARD_PAGE_SIZE: int = 4096     # Windows page size; do not change

# Isolated subprocess timeout for call_buffer(isolated=True).
ISOLATED_CALL_TIMEOUT_S: float = 10.0
ISOLATED_JOIN_TIMEOUT_S: float = 2.0

# Maximum constant value extracted from pseudocode (> this → likely a VA, not a constant).
PROBE_MAX_CONST: int = (1 << 32) - 1

# Default probe base count (number of consecutive integers starting from 0).
PROBE_DEFAULT_MAX_BASE: int = 64

# Default derivative bits (how many bit-flip probes per input).
PROBE_DEFAULT_DERIV_BITS: int = 8


# ── calibration writer (called by `cli.py calibrate`) ────────────────────────

def write_calibration(values: dict) -> None:
    """Persist calibrated values to calibration.json."""
    existing = _load_calibration()
    existing.update(values)
    with open(_CAL_PATH, "w") as f:
        _json.dump(existing, f, indent=2)
    print(f"Calibration written to {_CAL_PATH}")
    for k, v in values.items():
        print(f"  {k} = {v}")


def print_summary() -> None:
    """Print all constants grouped by category."""
    cal_keys = {
        "stateful_timing_cv_threshold": STATEFUL_TIMING_CV_THRESHOLD,
        "ipsampler_interval_us": IPSAMPLER_INTERVAL_US,
        "ipsampler_n_iters": IPSAMPLER_N_ITERS,
        "ipsampler_min_samples": IPSAMPLER_MIN_SAMPLES,
        "context_replay_n_runs": CONTEXT_REPLAY_N_RUNS,
    }
    print("MACHINE_CALIBRATED (run `cli.py calibrate` to update):")
    cal_present = _os.path.exists(_CAL_PATH)
    for k, v in cal_keys.items():
        src = "calibrated" if (cal_present and k in _cal) else "default"
        print(f"  {k:<42} = {v}  [{src}]")
    print()
    print("EMPIRICAL (measured 2026-06-19, 111-function sweep, 93.7% acc):")
    empirical = {
        "STATEFUL_TIMING_CV_THRESHOLD": STATEFUL_TIMING_CV_THRESHOLD,
        "EXACT_THRESHOLD": EXACT_THRESHOLD,
        "XOR_LINEAR_CIPHER_THRESHOLD": XOR_LINEAR_CIPHER_THRESHOLD,
        "PRNG_AVALANCHE_MIN": PRNG_AVALANCHE_MIN,
        "HASH_AVALANCHE_MIN": HASH_AVALANCHE_MIN,
        "GUARD_SENTINEL_DOMINANT": GUARD_SENTINEL_DOMINANT,
        "TIER3_DISCRIMINANT_THRESHOLD": TIER3_DISCRIMINANT_THRESHOLD,
        "KB_EMIT_CONFIDENCE": KB_EMIT_CONFIDENCE,
    }
    for k, v in empirical.items():
        print(f"  {k:<42} = {v}")
    print()
    print("STRUCTURAL (fixed by design):")
    structural = {
        "FINGERPRINT_BITS": FINGERPRINT_BITS,
        "WHT_BITS": WHT_BITS,
        "KB_INVARIANT_LAYERS": KB_INVARIANT_LAYERS,
        "KB_INVARIANT_COUNT": KB_INVARIANT_COUNT,
        "GUARD_PAGE_SIZE": GUARD_PAGE_SIZE,
        "PROBE_MAX_CONST": hex(PROBE_MAX_CONST),
    }
    for k, v in structural.items():
        print(f"  {k:<42} = {v}")


if __name__ == "__main__":
    print_summary()
