"""
dynamic/classify.py — Function class identification from behavioral metrics.

Takes FingerprintMetrics + the ProbeSet (for domain_const_frac) and produces a
ClassifyResult: function class, confidence, identified algorithm if known, and
an LLM-ready hint string that collapses FUNCTION_IDENTIFICATION_STRIPPED from H=2
toward H=1.

Classification hierarchy
------------------------
1. EXACT MATCH  — known_vectors.best_match() score > EXACT_THRESHOLD (0.90)
                  → name the algorithm directly: "this is xorshift64"
2. CLASS MATCH  — metric profile rules identify the broad class
                  → "this is a hash/PRNG/checksum/guard"
3. DOMAIN HINT  — high fraction of constants match Windows/extension dictionaries
                  → "uses Windows API constants, likely domain function not algorithm"
4. UNKNOWN      — insufficient signal
                  → raw metrics returned as hint, no classification

Function classes
----------------
  prng       — pseudo-random number generator; bijective, high avalanche
  hash       — hash step/finalizer; high avalanche, many-to-one
  checksum   — CRC/Adler/Fletcher; structured output, table-driven
  cipher     — XOR stream cipher or block cipher round; XOR-linear
  arith      — arithmetic: multiply, scale, fixed-point, linear transform
  guard      — input validation / bounds check; high sentinel_frac
  domain     — Windows API / game state / protocol dispatch; branchy timing +
                domain constants; NOT an algorithm
  constant   — always returns the same value; degenerate
  identity   — f(x) ≈ x; passthrough
  unknown    — insufficient signal to classify

LLM hint injection
------------------
The llm_hint field is designed to be prepended to the Ghidra calltree prompt:

    BEHAVIORAL_FINGERPRINT: FUN_1800abcd0 — xorshift64 PRNG (score=0.98).
    I/O evidence: f(1)=0xa000, f(2)=0x14000, ... entropy=0.97 avalanche=0.49.
    This collapses FUNCTION_IDENTIFICATION_STRIPPED for this function.

CLI
---
    py re_toolkit/dynamic/classify.py --dll foo.dll --func 0x1800abcd0 [--code pseudo.c]
    py re_toolkit/dynamic/classify.py --dll foo.dll --func xorshift_nonzero_test
"""
from __future__ import annotations
import json, sys, os, argparse
from dataclasses import dataclass, asdict

try:
    from .fingerprint   import FingerprintMetrics, compute as fp_compute
    from .known_vectors import KnownVector, KNOWN_VECTORS, best_match
    from .probe         import ProbeBuilder, default_probe_set, ProbeSet
    from .execute       import DLLExecutor, ExecuteResult
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from fingerprint   import FingerprintMetrics, compute as fp_compute  # type: ignore
    from known_vectors import KnownVector, KNOWN_VECTORS, best_match      # type: ignore
    from probe         import ProbeBuilder, default_probe_set, ProbeSet   # type: ignore
    from execute       import DLLExecutor, ExecuteResult                  # type: ignore

# ── thresholds (all sourced from constants.py — edit there, not here) ─────────

try:
    from .constants import (
        EXACT_THRESHOLD, CLASS_THRESHOLD, DOMAIN_CONST_FRAC,
        STATEFUL_TIMING_CV_THRESHOLD, KB_EMIT_CONFIDENCE,
        XOR_LINEAR_CIPHER_THRESHOLD, MONOTONE_ARITH_THRESHOLD,
        ARITH_LINEAR_DELTA_CV, PRNG_AVALANCHE_MIN, PRNG_BIJECTIVITY_MIN,
        PRNG_ENTROPY_MIN, HASH_AVALANCHE_MIN, HASH_ENTROPY_MIN,
        CHECKSUM_BIJECTIVITY_MAX, CHECKSUM_ENTROPY_MIN, CHECKSUM_AVALANCHE_MAX,
        GUARD_SENTINEL_DOMINANT, GUARD_SENTINEL_SECONDARY, GUARD_AVALANCHE_MAX,
        GUARD_HINT_FRAC, DOMAIN_TIMING_CV_BRANCHY, DOMAIN_TIMING_CV_FLAT,
        UNKNOWN_AVALANCHE_FLOOR, UNKNOWN_SENTINEL_FLOOR,
        UNKNOWN_MONOTONE_FLOOR, UNKNOWN_XOR_FLOOR,
    )
except ImportError:
    from constants import (                                              # type: ignore
        EXACT_THRESHOLD, CLASS_THRESHOLD, DOMAIN_CONST_FRAC,
        STATEFUL_TIMING_CV_THRESHOLD, KB_EMIT_CONFIDENCE,
        XOR_LINEAR_CIPHER_THRESHOLD, MONOTONE_ARITH_THRESHOLD,
        ARITH_LINEAR_DELTA_CV, PRNG_AVALANCHE_MIN, PRNG_BIJECTIVITY_MIN,
        PRNG_ENTROPY_MIN, HASH_AVALANCHE_MIN, HASH_ENTROPY_MIN,
        CHECKSUM_BIJECTIVITY_MAX, CHECKSUM_ENTROPY_MIN, CHECKSUM_AVALANCHE_MAX,
        GUARD_SENTINEL_DOMINANT, GUARD_SENTINEL_SECONDARY, GUARD_AVALANCHE_MAX,
        GUARD_HINT_FRAC, DOMAIN_TIMING_CV_BRANCHY, DOMAIN_TIMING_CV_FLAT,
        UNKNOWN_AVALANCHE_FLOOR, UNKNOWN_SENTINEL_FLOOR,
        UNKNOWN_MONOTONE_FLOOR, UNKNOWN_XOR_FLOOR,
    )

# ── extension dict paths (for domain_const_frac) ──────────────────────────────
# We load the same extension JSON files used by ghidra_dump_calltree.py
_EXT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),  # re_toolkit/
    "extensions"
)


def _load_extension_constants() -> set[int]:
    """Load all known Windows/API constants from the extensions/ JSON files."""
    known: set[int] = set()
    if not os.path.isdir(_EXT_DIR):
        return known
    import glob
    for path in glob.glob(os.path.join(_EXT_DIR, "*.json")):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                ext = json.load(f)
            for entry in ext.get("constants", []):
                v = entry.get("value")
                if isinstance(v, int):
                    known.add(v)
                elif isinstance(v, str):
                    try:
                        known.add(int(v, 0))
                    except ValueError:
                        pass
        except Exception:
            pass
    return known


_EXTENSION_CONSTANTS: set[int] | None = None


def _get_extension_constants() -> set[int]:
    global _EXTENSION_CONSTANTS
    if _EXTENSION_CONSTANTS is None:
        _EXTENSION_CONSTANTS = _load_extension_constants()
    return _EXTENSION_CONSTANTS


# ── result type ───────────────────────────────────────────────────────────────

@dataclass
class ClassifyResult:
    func_id:         str           # FUN_* or export name
    func_class:      str           # prng / hash / checksum / cipher / arith / guard / domain / unknown
    confidence:      float         # 0-1; 1.0 only for exact I/O match
    primary_algo:    str | None    # exact algorithm name if identified ("xorshift64"), else None
    algo_score:      float         # I/O match score for primary_algo (0 if unknown)
    domain_const_frac: float       # fraction of pseudocode constants in Windows extension dict
    evidence:        list[str]     # human-readable evidence items
    synopsis:        str           # metrics synopsis from FingerprintMetrics.synopsis()
    llm_hint:        str           # one-line hint ready for LLM prompt injection
    metrics:         dict          # full FingerprintMetrics as dict

    def to_json(self, indent: int = 2) -> str:
        d = asdict(self)
        return json.dumps(d, indent=indent)


# ── classification rules ──────────────────────────────────────────────────────

def _class_from_metrics(m: FingerprintMetrics) -> tuple[str, float, list[str]]:
    """
    Apply rule-based class detection from metric values.
    Returns (func_class, confidence, evidence_list).
    Rules are ordered by specificity; first match wins.
    """
    ev: list[str] = []

    if m.is_constant:
        # High timing variance on a constant-output function means internal branching /
        # side effects — the function does real work but doesn't expose it via return value.
        # Threshold 0.5: a pure `return K;` has near-zero timing_cv; stateful logic does not.
        if m.timing_cv > STATEFUL_TIMING_CV_THRESHOLD:
            ev.append(f"all outputs identical but timing_cv={m.timing_cv:.3f} → internal state or side effects")
            return "stateful", 0.80, ev
        ev.append("all outputs identical")
        return "constant", 0.95, ev

    if m.is_near_identity:
        ev.append(f"mean |f(x)-x|/|x| < 1%")
        return "identity", 0.90, ev

    if m.is_boolean:
        ev.append("all outputs in {0, 1}")
        if m.sentinel_frac > GUARD_SENTINEL_DOMINANT:
            ev.append(f"sentinel={m.sentinel_value:#x} in {m.sentinel_frac:.0%} of probes")
            return "guard", 0.80, ev
        return "guard", 0.70, ev

    # Guard / early-exit: dominant sentinel + bounded output + no avalanche
    if m.sentinel_frac > GUARD_SENTINEL_SECONDARY and m.avalanche_mean < GUARD_AVALANCHE_MAX:
        ev.append(f"sentinel={m.sentinel_value:#x} in {m.sentinel_frac:.0%} of probes (guard)")
        ev.append(f"avalanche={m.avalanche_mean:.3f} (low → not hash)")
        return "guard", 0.75, ev

    # XOR cipher / linear: almost all D_k f constant across x
    if m.xor_linear_frac > XOR_LINEAR_CIPHER_THRESHOLD:
        ev.append(f"deriv_const_frac={m.xor_linear_frac:.3f} → XOR-linear")
        return "cipher", 0.80, ev

    # Arithmetic / monotone
    if m.monotone_inc_frac > MONOTONE_ARITH_THRESHOLD or m.monotone_dec_frac > MONOTONE_ARITH_THRESHOLD:
        ev.append(f"monotone_inc={m.monotone_inc_frac:.3f}, monotone_dec={m.monotone_dec_frac:.3f}")
        if m.first_diff_cv < ARITH_LINEAR_DELTA_CV:
            ev.append(f"first_diff_cv={m.first_diff_cv:.4f} (constant delta → linear)")
        return "arith", 0.75, ev

    # PRNG: high avalanche + bijective + high entropy
    if (m.avalanche_mean > PRNG_AVALANCHE_MIN
            and m.bijectivity > PRNG_BIJECTIVITY_MIN
            and m.entropy_norm > PRNG_ENTROPY_MIN):
        ev.append(f"avalanche={m.avalanche_mean:.3f} (≥{PRNG_AVALANCHE_MIN})")
        ev.append(f"bijectivity={m.bijectivity:.3f} (≥{PRNG_BIJECTIVITY_MIN})")
        ev.append(f"entropy={m.entropy_norm:.3f}")
        return "prng", 0.70, ev

    # Hash / finalizer: high avalanche + high entropy but many-to-one
    if m.avalanche_mean > HASH_AVALANCHE_MIN and m.entropy_norm > HASH_ENTROPY_MIN:
        ev.append(f"avalanche={m.avalanche_mean:.3f}")
        ev.append(f"entropy={m.entropy_norm:.3f}")
        ev.append(f"bijectivity={m.bijectivity:.3f} (hash many-to-one)")
        return "hash", 0.65, ev

    # Checksum: structured output, not bijective, not hash-level avalanche
    # (rule reads after hash so only fires when hash rule didn't)
    if (m.bijectivity < CHECKSUM_BIJECTIVITY_MAX
            and m.entropy_norm > CHECKSUM_ENTROPY_MIN
            and m.avalanche_mean < CHECKSUM_AVALANCHE_MAX):
        ev.append(f"bijectivity={m.bijectivity:.3f} (many-to-one)")
        ev.append(f"avalanche={m.avalanche_mean:.3f} (below hash threshold)")
        return "checksum", 0.55, ev

    return "unknown", 0.30, ["no metric profile matched"]


# ── main entry point ──────────────────────────────────────────────────────────

def classify(
    metrics:       FingerprintMetrics,
    probe_set:     ProbeSet | None = None,
    io_map:        dict[int, int] | None = None,
    pseudocode:    str = "",
) -> ClassifyResult:
    """
    Classify a function from its FingerprintMetrics.

    Parameters
    ----------
    metrics    : from fingerprint.compute()
    probe_set  : from ProbeBuilder.build() — used to compute domain_const_frac
    io_map     : {arg0: retval} — for exact known-vector matching
    pseudocode : raw pseudocode — used for domain_const_frac if probe_set not given
    """
    evidence: list[str] = []

    # ── 1. domain constant fraction ───────────────────────────────────────────
    if probe_set is not None:
        code_consts = {int(k, 16) for k in probe_set.constants_found}
    elif pseudocode:
        from probe import ProbeBuilder  # type: ignore
        pb          = ProbeBuilder(pseudocode)
        consts, _   = pb._extract_constants()
        code_consts = consts
    else:
        code_consts = set()

    ext_consts       = _get_extension_constants()
    if code_consts:
        domain_hits      = code_consts & ext_consts
        domain_const_frac = len(domain_hits) / len(code_consts)
    else:
        domain_const_frac = 0.0

    # ── 2. exact known-vector matching (I/O test) ─────────────────────────────
    primary_algo = None
    algo_score   = 0.0
    match_class  = None

    if io_map:
        ranked = best_match(io_map, metrics=metrics)
        if ranked and ranked[0].score >= CLASS_THRESHOLD:
            top = ranked[0]
            algo_score  = top.score
            match_class = top.vector.func_class
            if top.score >= EXACT_THRESHOLD:
                primary_algo = top.vector.name
                evidence.append(
                    f"EXACT_MATCH: {top.vector.name} score={top.score:.3f} "
                    f"({top.matches}/{top.total} I/O pairs)"
                )
            else:
                evidence.append(
                    f"LIKELY_MATCH: {top.vector.name} score={top.score:.3f} "
                    f"(below {EXACT_THRESHOLD} threshold)"
                )

    # ── 3. metric-based class detection ──────────────────────────────────────
    class_from_metrics, class_confidence, class_evidence = _class_from_metrics(metrics)
    evidence.extend(class_evidence)

    # ── 4. domain override ────────────────────────────────────────────────────
    if domain_const_frac >= DOMAIN_CONST_FRAC and primary_algo is None:
        evidence.append(
            f"DOMAIN_CONST_FRAC={domain_const_frac:.2f} ≥ {DOMAIN_CONST_FRAC} "
            f"(constants match Windows API extension dictionaries)"
        )
        if class_from_metrics in ("unknown", "guard"):
            class_from_metrics = "domain"
            class_confidence   = 0.60

    # ── 5. timing hint ────────────────────────────────────────────────────────
    if metrics.timing_cv > DOMAIN_TIMING_CV_BRANCHY:
        evidence.append(f"timing_cv={metrics.timing_cv:.3f} (branchy; consistent with domain/FSM)")
    elif metrics.timing_cv < DOMAIN_TIMING_CV_FLAT:
        evidence.append(f"timing_cv={metrics.timing_cv:.3f} (flat; consistent with hash/PRNG/arith)")

    # ── 6. resolve final class and confidence ─────────────────────────────────
    if primary_algo is not None:
        func_class  = match_class or class_from_metrics
        confidence  = min(1.0, algo_score)
    else:
        func_class  = match_class or class_from_metrics
        confidence  = class_confidence

    # ── 7. build LLM hint ─────────────────────────────────────────────────────
    llm_hint = _build_llm_hint(
        metrics, func_class, confidence, primary_algo, algo_score,
        domain_const_frac, io_map,
    )

    return ClassifyResult(
        func_id=metrics.func_id,
        func_class=func_class,
        confidence=round(confidence, 3),
        primary_algo=primary_algo,
        algo_score=round(algo_score, 3),
        domain_const_frac=round(domain_const_frac, 3),
        evidence=evidence,
        synopsis=metrics.synopsis(),
        llm_hint=llm_hint,
        metrics=metrics.to_dict(),
    )


def _build_llm_hint(
    m: FingerprintMetrics,
    func_class: str,
    confidence: float,
    primary_algo: str | None,
    algo_score: float,
    domain_const_frac: float,
    io_map: dict[int, int] | None,
) -> str:
    parts: list[str] = []

    if primary_algo and algo_score >= EXACT_THRESHOLD:
        parts.append(
            f"BEHAVIORAL_FINGERPRINT: {m.func_id} is {primary_algo} "
            f"(I/O match score={algo_score:.2f}, class={func_class})."
        )
    else:
        parts.append(
            f"BEHAVIORAL_FINGERPRINT: {m.func_id} — class={func_class} "
            f"confidence={confidence:.2f}."
        )

    parts.append(
        f"Metrics: avalanche={m.avalanche_mean:.3f}, entropy={m.entropy_norm:.3f}, "
        f"bijective={m.bijectivity:.3f}, monotone_inc={m.monotone_inc_frac:.3f}, "
        f"xor_linear={m.xor_linear_frac:.3f}, timing_cv={m.timing_cv:.3f}."
    )

    if m.sentinel_frac > GUARD_HINT_FRAC:
        parts.append(
            f"Guard signal: {m.sentinel_frac:.0%} of probes return sentinel={m.sentinel_value:#x}."
        )

    if domain_const_frac >= DOMAIN_CONST_FRAC:
        parts.append(
            f"Domain signal: {domain_const_frac:.0%} of pseudocode constants match "
            f"Windows API extension dictionaries."
        )

    if io_map:
        sample = list(io_map.items())[:4]
        sample_str = ", ".join(f"f({x:#x})={v:#x}" for x, v in sample)
        parts.append(f"Sample I/O: {sample_str}.")

    if func_class == "stateful":
        parts.append(
            f"STATEFUL FUNCTION: return value is constant but timing_cv={m.timing_cv:.3f} "
            f"indicates internal branching and side effects. "
            f"Primary observable behavior is mutation of global or heap state, not return value. "
            f"Static analysis (calltree) is the primary evidence source. "
            f"Memory observation (before/after snapshot of writable globals) required to map state transitions."
        )

    if func_class == "unknown":
        reasons = []
        if m.avalanche_mean < UNKNOWN_AVALANCHE_FLOOR:
            reasons.append(
                f"avalanche={m.avalanche_mean:.2f} < {UNKNOWN_AVALANCHE_FLOOR} (below hash/PRNG threshold)"
            )
        if m.sentinel_frac < UNKNOWN_SENTINEL_FLOOR:
            reasons.append(
                f"sentinel_frac={m.sentinel_frac:.2f} < {UNKNOWN_SENTINEL_FLOOR} (no dominant guard value)"
            )
        if m.monotone_inc_frac < UNKNOWN_MONOTONE_FLOOR and m.monotone_dec_frac < UNKNOWN_MONOTONE_FLOOR:
            reasons.append(
                f"monotone_inc={m.monotone_inc_frac:.2f} < {UNKNOWN_MONOTONE_FLOOR} (not arithmetic/linear)"
            )
        if m.xor_linear_frac < UNKNOWN_XOR_FLOOR:
            reasons.append(
                f"xor_linear={m.xor_linear_frac:.2f} < {UNKNOWN_XOR_FLOOR} (not XOR-cipher)"
            )
        if reasons:
            parts.append(
                f"No metric class matched ({'; '.join(reasons)}). "
                f"Likely causes: multi-argument function (only arg[0] varied), "
                f"stateful/init-dependent, or pointer-argument function. "
                f"Use pseudocode structure as primary evidence."
            )

    return "  ".join(parts)


# ── convenience wrapper ───────────────────────────────────────────────────────

def run(
    executor:   DLLExecutor,
    func:       int | str,
    pseudocode: str  = "",
    n_args:     int  = 1,
    bits:       int  = 64,
    tier3:      bool = True,
    is_simd:    bool = False,
) -> ClassifyResult:
    """
    Full pipeline: probe → execute → fingerprint → classify → (optional) Tier 3.

    Parameters
    ----------
    executor   : DLLExecutor with the DLL already loaded
    func       : Ghidra VA (int) or export name (str)
    pseudocode : Ghidra pseudocode for path-stratified probing + domain detection
    n_args     : fallback arg count if pseudocode is empty
    bits       : assumed output bit width
    tier3      : if True, escalate to runtime_probe.run_tier3() when confidence < 0.70
    is_simd    : True when static analysis flagged SIMD vectorization. Skips pseudocode
                 path-stratification (unreliable) and forces smart boundary probing
                 that maximizes discrimination for scalar-equivalent SIMD functions.
    """
    # SIMD_SMART_PROBES: boundary-rich set that maximizes discrimination for
    # scalar-equivalent functions where pseudocode is unreliable.
    # Covers: identity, arithmetic, bitwise, prime/composite, range patterns.
    _SIMD_PROBES = [
        [0],[1],[2],[3],[4],[5],[6],[7],[8],[9],[10],[12],[15],[16],
        [32],[64],[97],[100],[127],[128],[255],[256],[1023],[1024],
    ]

    ps = ProbeBuilder(pseudocode).build() if pseudocode else default_probe_set(n_args)

    if is_simd:
        # SIMD: run high-density simulation now, use smart probes for fingerprint metrics.
        # nano_sim runs 2048+ probes and selects the maximally discriminating subset.
        # This replaces the pseudocode-derived probe strategy.
        call_seq = _SIMD_PROBES   # used for fingerprint metrics (avalanche etc.)
    else:
        call_seq = ps.call_args()
    results = executor.call_batch(func, call_seq)
    metrics = fp_compute(results, ps, bits=bits)
    io_map  = {r.args[0]: r.retval for r in results if r.retval is not None and r.args}
    cr      = classify(metrics, probe_set=ps, io_map=io_map, pseudocode=pseudocode)

    # ── Tier 3 escalation ────────────────────────────────────────────────────
    if tier3 and cr.confidence < CLASS_THRESHOLD:
        try:
            try:
                from .runtime_probe import run_tier3
            except ImportError:
                from runtime_probe import run_tier3  # type: ignore
            t3 = run_tier3(executor, func, ps, metrics)
            if t3 is not None:
                cr.evidence.append(
                    f"TIER3: ip={t3.ip_pattern} purity={'pure' if t3.is_pure else 'impure' if t3.is_pure is False else '?'} "
                    f"ret={t3.ret_bits}bit n_args≈{t3.n_args_detected}"
                )
                cr.llm_hint = cr.llm_hint + "  " + t3.llm_hint
        except (NotImplementedError, Exception):
            pass   # non-Windows or unexpected error — Tier 3 is best-effort

    # ── SIMD nano-simulation I/O injection ───────────────────────────────────
    # When SIMD-detected: run high-density simulation (2048+ probes, sub-ms),
    # select maximally discriminating I/O pairs, embed in LLM hint.
    # The discriminating selection covers: one example per distinct output value +
    # transition boundaries + stratified magnitudes — typically 16-20 pairs.
    if is_simd:
        try:
            try:
                from .nano_sim import nano_sim as _nano_sim
            except ImportError:
                from nano_sim import _nano_sim  # type: ignore
            ns = _nano_sim(executor, func, n_probes=2048, n_display=20)
            cr.llm_hint = ns["llm_hint"] + "\n" + cr.llm_hint
            cr.evidence.append(
                f"SIMD_NANOSIM: {ns['n_probed']} probes, "
                f"{ns['n_distinct']} distinct outputs, "
                f"{len(ns['pairs'])} discriminating pairs selected"
            )
        except Exception:
            pass   # best-effort

    # Memory observer is NOT auto-triggered here — pre-warming 6 calls before
    # call_batch shifts timing_cv on borderline functions and causes regressions.
    # Use: cli.py memory-observe <dll> <func>  for standalone memory observation,
    # or pass memory_transitions= kwarg if you've already collected them externally.

    # ── Knowledge bus emit ────────────────────────────────────────────────────
    # Emit function identification so memscan/frida can escalate stability when
    # they independently confirm the same finding.
    if cr.confidence >= KB_EMIT_CONFIDENCE:
        try:
            import sys as _sys, os as _os
            # Prefer the already-imported module instance (shares KNOWLEDGE_JSON).
            # A bare 'import knowledge_bus' creates a separate instance with its
            # own global path, so it would write to the wrong file.
            _kb_mod = (
                _sys.modules.get("re_toolkit.knowledge_bus") or
                _sys.modules.get("knowledge_bus")
            )
            if _kb_mod is None:
                _kb_dir = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
                if _kb_dir not in _sys.path:
                    _sys.path.insert(0, _kb_dir)
                import knowledge_bus as _kb_mod
            _va_hex = hex(func) if isinstance(func, int) else None
            _payload = {
                "func_id":    cr.func_id,
                "va":         _va_hex,
                "class":      cr.func_class,
                "confidence": round(cr.confidence, 3),
            }
            if cr.primary_algo:
                _payload["algo"]       = cr.primary_algo
                _payload["algo_score"] = round(cr.algo_score, 3)
            _obs_type = "function_algo" if cr.primary_algo else "function_class"
            _kb_mod.emit_discovery("dynamic", _obs_type, _payload)
        except Exception:
            pass   # knowledge_bus optional; gracefully absent in standalone use

    return cr


# ── Self-test ─────────────────────────────────────────────────────────────────

def _verify():
    """
    Fast sanity check for classify.py — runs in < 5s, no DLL required.
    Tests the metric → class mapping rules directly via synthetic FingerprintMetrics.
    """
    import tempfile, ctypes as _ct

    # Build a minimal FingerprintMetrics-like object for rule testing
    from dynamic.fingerprint import FingerprintMetrics  # type: ignore

    def _make(is_constant=False, is_boolean=False, is_near_identity=False,
              timing_cv=0.0, sentinel_frac=0.0, sentinel_value=0,
              xor_linear_frac=0.0, monotone_inc_frac=0.0, monotone_dec_frac=0.0,
              avalanche_mean=0.0, entropy_norm=0.0, bijectivity=0.0,
              first_diff_cv=1.0, algebraic_degree=-1):
        m = object.__new__(FingerprintMetrics)
        m.func_id = "TEST"
        m.is_constant = is_constant
        m.is_boolean = is_boolean
        m.is_near_identity = is_near_identity
        m.timing_cv = timing_cv
        m.sentinel_frac = sentinel_frac
        m.sentinel_value = sentinel_value
        m.xor_linear_frac = xor_linear_frac
        m.monotone_inc_frac = monotone_inc_frac
        m.monotone_dec_frac = monotone_dec_frac
        m.avalanche_mean = avalanche_mean
        m.entropy_norm = entropy_norm
        m.bijectivity = bijectivity
        m.first_diff_cv = first_diff_cv
        m.algebraic_degree = algebraic_degree
        return m

    # POSITIVE: genuine constant (low timing_cv) → "constant"
    cls, conf, _ = _class_from_metrics(_make(is_constant=True, timing_cv=0.05))
    assert cls == "constant", f"Expected constant, got {cls}"
    assert conf == 0.95

    # POSITIVE: constant output but high timing_cv → "stateful"
    cls, conf, _ = _class_from_metrics(_make(is_constant=True, timing_cv=0.20))
    assert cls == "stateful", f"Expected stateful, got {cls}"

    # BOUNDARY: exactly at threshold → constant (threshold is exclusive >)
    cls, _, _ = _class_from_metrics(_make(is_constant=True, timing_cv=STATEFUL_TIMING_CV_THRESHOLD))
    assert cls == "constant", f"At threshold should be constant, got {cls}"

    # POSITIVE: boolean outputs + high sentinel → guard
    cls, _, _ = _class_from_metrics(_make(is_boolean=True, sentinel_frac=0.8, sentinel_value=0))
    assert cls == "guard"

    # POSITIVE: XOR-linear → cipher
    cls, _, _ = _class_from_metrics(_make(xor_linear_frac=0.90))
    assert cls == "cipher"

    # POSITIVE: high avalanche + high entropy + bijective → prng
    cls, _, _ = _class_from_metrics(_make(avalanche_mean=0.45, entropy_norm=0.80, bijectivity=0.75))
    assert cls == "prng"

    # POSITIVE: high avalanche + high entropy, NOT bijective → hash
    cls, _, _ = _class_from_metrics(_make(avalanche_mean=0.40, entropy_norm=0.65, bijectivity=0.30))
    assert cls == "hash"

    # POSITIVE: monotone → arith
    cls, _, _ = _class_from_metrics(_make(monotone_inc_frac=0.85))
    assert cls == "arith"

    # POSITIVE: no signal → unknown
    cls, _, _ = _class_from_metrics(_make())
    assert cls == "unknown"

    print(f"OK: classify.py _verify() passed")
    print(f"  STATEFUL_TIMING_CV_THRESHOLD={STATEFUL_TIMING_CV_THRESHOLD}")
    print(f"  All class rules: constant/stateful/guard/cipher/prng/hash/arith/unknown")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Classify a DLL function via behavioral fingerprinting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--dll",      required=True,  help="Path to the DLL")
    ap.add_argument("--func",     required=True,  help="Export name or Ghidra VA (0x...)")
    ap.add_argument("--code",     default="",     help="Pseudocode file (.c / .txt)")
    ap.add_argument("--n-args",   type=int, default=1, help="Arg count fallback")
    ap.add_argument("--bits",     type=int, default=64, help="Output bit width")
    ap.add_argument("--hint",     action="store_true", help="Print only llm_hint (for pipe use)")
    ap.add_argument("--synopsis", action="store_true", help="Print only synopsis line")
    opts = ap.parse_args()

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from dynamic.execute import DLLExecutor as _Ex
    except ImportError:
        from execute import DLLExecutor as _Ex  # type: ignore

    ex   = _Ex(opts.dll)
    func = int(opts.func, 16) if opts.func.startswith("0x") else opts.func
    code = ""
    if opts.code:
        with open(opts.code, 'r', encoding='utf-8', errors='replace') as f:
            code = f.read()

    result = run(ex, func, pseudocode=code, n_args=opts.n_args, bits=opts.bits)

    if opts.hint:
        print(result.llm_hint)
    elif opts.synopsis:
        print(result.synopsis)
    else:
        print(result.to_json())
