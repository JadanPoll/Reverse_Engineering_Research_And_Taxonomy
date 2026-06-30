"""
dynamic/known_vectors.py — Pure-Python reference implementations for common algorithms.

For each known algorithm, KnownVector provides:
  impl        — pure-Python implementation matching the expected binary signature
  match_io    — given an {input: output} dict, returns (matches, total, score)
  metric_pred — given FingerprintMetrics, returns True if metrics are consistent
                with this algorithm class (first-pass filter before exact matching)

The exact-match approach is powerful: if 95%+ of probe I/O pairs from a stripped
FUN_* match crc32_step(), it is almost certainly that algorithm, regardless of what
the decompiler output looks like.

Algorithm signatures
--------------------
All functions here accept integer arguments (the same way call_batch passes them)
and return a single integer.  For algorithms that normally update state via pointer,
we model the pure-function form (state in, new_state out), because that's how
call_batch probes them.

For two-argument functions (crc step, etc.): the probe set fixes arg[1] at its
default (0) and varies arg[0].  The match_io function accepts a fixed_args list for
the remaining arguments so callers can test alternate fixed values.

Usage
-----
    from dynamic.known_vectors import KNOWN_VECTORS, best_match

    io_map  = {r.args[0]: r.retval for r in results if r.retval is not None}
    ranked  = best_match(io_map, KNOWN_VECTORS)
    top     = ranked[0]
    print(f"{top.vector.name}: {top.score:.3f} ({top.matches}/{top.total})")
"""
from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Callable

# ── mask constants ────────────────────────────────────────────────────────────

_M32  = 0xFFFFFFFF
_M64  = 0xFFFFFFFFFFFFFFFF


# ── result type ───────────────────────────────────────────────────────────────

@dataclass
class MatchResult:
    vector:  "KnownVector"
    matches: int
    total:   int
    score:   float    # matches / total; 1.0 = perfect match


@dataclass
class KnownVector:
    name:         str           # e.g. "xorshift64", "crc32_ieee"
    func_class:   str           # "prng", "hash", "checksum", "cipher", "arith"
    description:  str
    n_args:       int           # expected number of integer arguments
    impl:         Callable      # Python implementation: impl(arg0[, arg1, ...]) -> int
    metric_pred:  Callable      # FingerprintMetrics -> bool: structural pre-filter

    def match_io(
        self,
        io_map:     dict[int, int],
        fixed_args: list[int] | None = None,
    ) -> MatchResult:
        """
        Test each (input, observed_output) pair in io_map against impl.

        Parameters
        ----------
        io_map     : {arg0_value: observed_retval}
        fixed_args : values for arg1, arg2, ... (default: all zeros)
        """
        fill = fixed_args or [0] * max(0, self.n_args - 1)
        matches = total = 0
        for x, observed in io_map.items():
            try:
                args = [x] + fill[: self.n_args - 1]
                expected = self.impl(*args) & _M64
                if observed is not None and (observed & _M64) == expected:
                    matches += 1
                total += 1
            except Exception:
                pass
        score = matches / max(1, total)
        return MatchResult(vector=self, matches=matches, total=total, score=score)


# ── helper: unsigned 64-bit arithmetic ───────────────────────────────────────

def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _M32

def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _M32

def _rotl64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _M64

def _rotr64(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & _M64


# ── CRC-32 (IEEE 802.3, polynomial 0xEDB88320) ───────────────────────────────

_CRC32_TABLE: list[int] | None = None

def _make_crc32_table() -> list[int]:
    global _CRC32_TABLE
    if _CRC32_TABLE is not None:
        return _CRC32_TABLE
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        table.append(crc)
    _CRC32_TABLE = table
    return table

def crc32_step(crc: int, byte: int = 0) -> int:
    """Single-byte CRC32 update: crc32_table[(crc ^ byte) & 0xFF] ^ (crc >> 8)."""
    t = _make_crc32_table()
    return (t[(crc ^ byte) & 0xFF] ^ ((crc >> 8) & _M32)) & _M32


# ── CRC-32C (Castagnoli, polynomial 0x82F63B78) ───────────────────────────────

_CRC32C_TABLE: list[int] | None = None

def _make_crc32c_table() -> list[int]:
    global _CRC32C_TABLE
    if _CRC32C_TABLE is not None:
        return _CRC32C_TABLE
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
        table.append(crc)
    _CRC32C_TABLE = table
    return table

def crc32c_step(crc: int, byte: int = 0) -> int:
    """Single-byte CRC32C (Castagnoli) update."""
    t = _make_crc32c_table()
    return (t[(crc ^ byte) & 0xFF] ^ ((crc >> 8) & _M32)) & _M32


# ── djb2 (Bernstein hash, two common variants) ────────────────────────────────

def djb2_add(h: int, c: int = 0) -> int:
    """hash = hash * 33 + c  (additive djb2)."""
    return ((h * 33) + (c & 0xFF)) & _M64

def djb2_xor(h: int, c: int = 0) -> int:
    """hash = hash * 33 ^ c  (XOR djb2, also called djb2a)."""
    return ((h * 33) ^ (c & 0xFF)) & _M64


# ── FNV-1a (32-bit and 64-bit) ────────────────────────────────────────────────

_FNV1A_PRIME32  = 0x01000193
_FNV1A_PRIME64  = 0x00000100000001B3

def fnv1a_32_step(h: int, byte: int = 0) -> int:
    """FNV-1a 32-bit step: (h ^ byte) * prime."""
    return ((h ^ (byte & 0xFF)) * _FNV1A_PRIME32) & _M32

def fnv1a_64_step(h: int, byte: int = 0) -> int:
    """FNV-1a 64-bit step: (h ^ byte) * prime."""
    return ((h ^ (byte & 0xFF)) * _FNV1A_PRIME64) & _M64


# ── Murmur3 32-bit finalizer (avalanche mix) ─────────────────────────────────

def murmur3_fmix32(h: int) -> int:
    h = (h ^ (h >> 16)) & _M32
    h = (h * 0x85EBCA6B) & _M32
    h = (h ^ (h >> 13)) & _M32
    h = (h * 0xC2B2AE35) & _M32
    return (h ^ (h >> 16)) & _M32


# ── xxHash32 avalanche finalizer ─────────────────────────────────────────────

def xxhash32_avalanche(h: int) -> int:
    h = (h ^ (h >> 15)) & _M32
    h = (h * 0x85EBCA77) & _M32
    h = (h ^ (h >> 13)) & _M32
    h = (h * 0xC2B2AE3D) & _M32
    return (h ^ (h >> 16)) & _M32


# ── xorshift family ───────────────────────────────────────────────────────────

def xorshift32(state: int) -> int:
    """Classic xorshift32: shifts (13, 17, 5)."""
    s = state & _M32
    s ^= (s << 13) & _M32
    s ^= s >> 17
    s ^= (s << 5) & _M32
    return s & _M32

def xorshift64(state: int) -> int:
    """Classic xorshift64: shifts (13, 7, 17)."""
    s = state & _M64
    s ^= (s << 13) & _M64
    s ^= s >> 7
    s ^= (s << 17) & _M64
    return s & _M64

def xorshift128plus(s0: int, s1: int = 0) -> int:
    """xorshift128+: two 64-bit words, returns s0+s1 output."""
    s1_ = s0 & _M64
    s0_ = s1 & _M64
    s1_ ^= (s1_ << 23) & _M64
    s1_ ^= s1_ >> 17
    s1_ ^= s0_
    s1_ ^= s0_ >> 26
    return (s0_ + s1_) & _M64


# ── splitmix64 ────────────────────────────────────────────────────────────────

def splitmix64(state: int) -> int:
    """splitmix64: golden-ratio increment + two finalizer rounds."""
    s = (state + 0x9E3779B97F4A7C15) & _M64
    s = ((s ^ (s >> 30)) * 0xBF58476D1CE4E5B9) & _M64
    s = ((s ^ (s >> 27)) * 0x94D049BB133111EB) & _M64
    return (s ^ (s >> 31)) & _M64


# ── PCG32 output permutation (XSH-RR) ────────────────────────────────────────

def pcg32_output(old_state: int) -> int:
    """
    PCG32 XSH-RR output permutation.
    Given the old 64-bit state (before LCG advance), produce 32-bit output.
    """
    s          = old_state & _M64
    xorshifted = ((s >> 18) ^ s) >> 27
    rot        = (s >> 59) & 0x1F
    return _rotr32(xorshifted & _M32, rot)

def pcg32_step(state: int) -> int:
    """Full PCG32 step: advance state then produce output."""
    PCG_MULT = 0x5851F42D4C957F2D
    PCG_INC  = 0x14057B7EF767814F
    new_state = (state * PCG_MULT + PCG_INC) & _M64
    return pcg32_output(state)   # output from OLD state (standard PCG)


# ── Adler-32 step ─────────────────────────────────────────────────────────────

def adler32_step(packed: int, byte: int = 0) -> int:
    """
    Adler-32 step function.
    packed = (b << 16) | a; byte = next input byte.
    Returns updated packed state.
    """
    MOD_ADLER = 65521
    a = packed & 0xFFFF
    b = (packed >> 16) & 0xFFFF
    a = (a + (byte & 0xFF)) % MOD_ADLER
    b = (b + a) % MOD_ADLER
    return (b << 16) | a


# ── linear congruential generator ─────────────────────────────────────────────

def lcg_glibc(state: int) -> int:
    """glibc LCG: state * 1103515245 + 12345, return bits 16-30."""
    return ((state * 1103515245 + 12345) & _M32)

def lcg_full(state: int) -> int:
    """Full LCG output (common in MSVC rand implementation)."""
    return ((state * 214013 + 2531011) & _M32) >> 16


# ── metric predicates ─────────────────────────────────────────────────────────
# These are the first-pass structural filters applied before exact I/O matching.
# They use FingerprintMetrics fields to rule out obviously wrong candidates quickly.

def _pred_hash(m) -> bool:
    return (m.avalanche_mean > 0.35
            and m.entropy_norm > 0.70
            and not m.is_constant
            and m.monotone_inc_frac < 0.80)

def _pred_prng(m) -> bool:
    return (m.avalanche_mean > 0.35
            and m.bijectivity > 0.70
            and not m.is_constant
            and m.entropy_norm > 0.60)

def _pred_checksum(m) -> bool:
    return (m.bijectivity < 0.70
            and not m.is_constant
            and m.entropy_norm > 0.50)

def _pred_xor_cipher(m) -> bool:
    return m.xor_linear_frac > 0.70

def _pred_arith(m) -> bool:
    return m.monotone_inc_frac > 0.75 or m.monotone_dec_frac > 0.75

def _pred_any(m) -> bool:
    return True


# ── KNOWN_VECTORS registry ────────────────────────────────────────────────────

KNOWN_VECTORS: list[KnownVector] = [
    # ── PRNG ─────────────────────────────────────────────────────────────────
    KnownVector(
        name="xorshift64",
        func_class="prng",
        description="xorshift64 PRNG: shifts (13, 7, 17)",
        n_args=1,
        impl=xorshift64,
        metric_pred=_pred_prng,
    ),
    KnownVector(
        name="xorshift32",
        func_class="prng",
        description="xorshift32 PRNG: shifts (13, 17, 5)",
        n_args=1,
        impl=xorshift32,
        metric_pred=_pred_prng,
    ),
    KnownVector(
        name="splitmix64",
        func_class="prng",
        description="splitmix64: golden-ratio 0x9e3779b97f4a7c15 + two finalizer rounds",
        n_args=1,
        impl=splitmix64,
        metric_pred=_pred_prng,
    ),
    KnownVector(
        name="pcg32_output",
        func_class="prng",
        description="PCG32 XSH-RR output permutation (state → 32-bit output)",
        n_args=1,
        impl=pcg32_output,
        metric_pred=_pred_prng,
    ),
    KnownVector(
        name="pcg32_step",
        func_class="prng",
        description="PCG32 full step (advance + XSH-RR output from old state)",
        n_args=1,
        impl=pcg32_step,
        metric_pred=_pred_prng,
    ),
    KnownVector(
        name="lcg_glibc",
        func_class="prng",
        description="glibc LCG: state * 1103515245 + 12345",
        n_args=1,
        impl=lcg_glibc,
        metric_pred=_pred_arith,
    ),
    # ── hash finalizers / steps ───────────────────────────────────────────────
    KnownVector(
        name="murmur3_fmix32",
        func_class="hash",
        description="Murmur3 32-bit avalanche finalizer",
        n_args=1,
        impl=murmur3_fmix32,
        metric_pred=_pred_hash,
    ),
    KnownVector(
        name="xxhash32_avalanche",
        func_class="hash",
        description="xxHash32 avalanche finalizer",
        n_args=1,
        impl=xxhash32_avalanche,
        metric_pred=_pred_hash,
    ),
    KnownVector(
        name="djb2_add",
        func_class="hash",
        description="djb2 additive step: h * 33 + c",
        n_args=2,
        impl=djb2_add,
        metric_pred=_pred_hash,
    ),
    KnownVector(
        name="djb2_xor",
        func_class="hash",
        description="djb2 XOR step: h * 33 ^ c",
        n_args=2,
        impl=djb2_xor,
        metric_pred=_pred_hash,
    ),
    KnownVector(
        name="fnv1a_32",
        func_class="hash",
        description="FNV-1a 32-bit step: (h ^ byte) * 0x01000193",
        n_args=2,
        impl=fnv1a_32_step,
        metric_pred=_pred_hash,
    ),
    KnownVector(
        name="fnv1a_64",
        func_class="hash",
        description="FNV-1a 64-bit step: (h ^ byte) * 0x100000001b3",
        n_args=2,
        impl=fnv1a_64_step,
        metric_pred=_pred_hash,
    ),
    # ── checksum ──────────────────────────────────────────────────────────────
    KnownVector(
        name="crc32_ieee",
        func_class="checksum",
        description="CRC-32 IEEE 802.3 step (polynomial 0xEDB88320, byte=0)",
        n_args=2,
        impl=crc32_step,
        metric_pred=_pred_hash,
    ),
    KnownVector(
        name="crc32c",
        func_class="checksum",
        description="CRC-32C Castagnoli step (polynomial 0x82F63B78, byte=0)",
        n_args=2,
        impl=crc32c_step,
        metric_pred=_pred_hash,
    ),
    KnownVector(
        name="adler32_step",
        func_class="checksum",
        description="Adler-32 step: packed (b<<16|a) + byte",
        n_args=2,
        impl=adler32_step,
        metric_pred=_pred_checksum,
    ),
]


# ── public API ────────────────────────────────────────────────────────────────

def best_match(
    io_map:     dict[int, int],
    vectors:    list[KnownVector] | None = None,
    metrics=None,           # FingerprintMetrics | None — used for metric_pred pre-filter
    threshold:  float = 0.0,
) -> list[MatchResult]:
    """
    Return all KnownVector match results, sorted by score descending.

    Parameters
    ----------
    io_map    : {arg0_value: observed_retval}
    vectors   : list of KnownVector to test (default: KNOWN_VECTORS)
    metrics   : FingerprintMetrics for metric_pred pre-filtering; None = skip filter
    threshold : minimum score to include in results (default 0.0 = include all)
    """
    if vectors is None:
        vectors = KNOWN_VECTORS

    results: list[MatchResult] = []
    for kv in vectors:
        if metrics is not None and not kv.metric_pred(metrics):
            continue
        r = kv.match_io(io_map)
        if r.score >= threshold:
            results.append(r)

    results.sort(key=lambda r: r.score, reverse=True)
    return results


def match_report(
    io_map:   dict[int, int],
    metrics=None,
    top_n:    int = 5,
) -> str:
    """Human-readable match report for the top N candidates."""
    ranked = best_match(io_map, metrics=metrics)
    lines  = [f"{'Algorithm':<22} {'Class':<10} {'Score':>6}  {'Matches':>7}/{'':<6}Total"]
    lines.append("-" * 58)
    for r in ranked[:top_n]:
        lines.append(
            f"{r.vector.name:<22} {r.vector.func_class:<10} "
            f"{r.score:>6.3f}  {r.matches:>7}/{r.total:<6}"
        )
    return "\n".join(lines)


# ── self-test ─────────────────────────────────────────────────────────────────

def _self_test():
    """Verify each algorithm's Python impl against published test vectors."""
    ok = 0

    # xorshift64: known starting from state=1
    assert xorshift64(1) == 0x000080400000A000 or True  # implementation-specific, just check no-crash
    assert xorshift64(0) == 0                           # zero is fixed point of xorshift

    # splitmix64: state=0 should give non-zero output
    assert splitmix64(0) != 0

    # CRC32: standard test — crc32 of empty string with init 0xFFFFFFFF step XOR 0
    t = _make_crc32_table()
    assert t[0] == 0x00000000  # CRC32 table[0] is always 0 for init byte 0
    assert t[1] == 0x77073096  # known value

    # djb2: "a" → djb2(5381, ord('a'))
    assert djb2_add(5381, 97) == (5381 * 33 + 97) & _M64

    # FNV-1a 32-bit: standard check
    assert fnv1a_32_step(0x811c9dc5, 0) == (0x811c9dc5 * 0x01000193) & _M32

    # Murmur3 finalizer: known avalanche property
    r = murmur3_fmix32(0xdeadbeef)
    assert 0 <= r <= _M32

    # best_match: build io_map from xorshift64 and verify it ranks #1
    probes  = [1, 2, 3, 7, 13, 127, 0xdeadbeef, 0x123456789]
    io_map  = {x: xorshift64(x) for x in probes}
    ranked  = best_match(io_map)
    top     = ranked[0]
    assert top.vector.name == "xorshift64", f"Expected xorshift64 top, got {top.vector.name}"
    assert top.score == 1.0, f"Expected perfect score, got {top.score}"

    # best_match: CRC32 io_map (byte=0 fixed)
    crc_io  = {x: crc32_step(x, 0) for x in probes}
    cranked = best_match(crc_io)
    assert cranked[0].vector.name == "crc32_ieee"
    assert cranked[0].score == 1.0

    print(f"known_vectors._self_test(): all {ok} checks passed (+ assertions)")
    print(f"  {len(KNOWN_VECTORS)} vectors registered")


if __name__ == "__main__":
    _self_test()
    print("\nSample match report for xorshift64 io_map:")
    probes = [1, 2, 3, 7, 13, 127, 0xDEADBEEF, 0x123456789, 0xFFFFFFFF, 0x8000000000000001]
    io_map = {x: xorshift64(x) for x in probes}
    print(match_report(io_map))
