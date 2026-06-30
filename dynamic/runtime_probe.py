"""
dynamic/runtime_probe.py — Tier 3 behavioral escalation.

Invoked by classify.run() only when Tier 1+2 metrics fail to discriminate
(discriminant = max(avalanche_mean, entropy_norm, sentinel_frac) - 0.5 < 0.3).

Two orthogonal mechanisms — neither measures time:

  ContextReplay  — run the same function N times with identical inputs and
                   compare outputs.  Detects side effects (impurity), scans
                   which arg positions actually affect the output (hidden args),
                   and infers the return-value width and signedness.

  IPSampler      — background thread suspends the probe thread at ~15µs
                   intervals while the probe thread loops the function call.
                   Builds a histogram of in-function RIP values.  Classifies
                   code-path shape: guard / flat / loop / branchy.

  run_tier3()    — gates on discriminant, orchestrates both, returns Tier3Result
                   with a ready-to-inject LLM hint string.

Windows-only: uses SuspendThread / GetThreadContext (no kernel driver needed).
Raises NotImplementedError on non-Windows at import time.

CLI
---
    py re_toolkit/dynamic/runtime_probe.py --dll foo.dll --func 0x1800abcd0
    py re_toolkit/dynamic/runtime_probe.py --dll foo.dll --func strlen --hint
"""
from __future__ import annotations
import ctypes, sys, os, time, threading, json, argparse
from dataclasses import dataclass, asdict
from collections import Counter

if sys.platform != "win32":
    raise NotImplementedError("runtime_probe.py requires Windows (SuspendThread / GetThreadContext)")

try:
    from .constants import (
        TIER3_DISCRIMINANT_THRESHOLD as TIER3_THRESHOLD,
        CONTEXT_REPLAY_N_RUNS, CONTEXT_REPLAY_N_TEST_ARGS,
        IPSAMPLER_INTERVAL_US, IPSAMPLER_N_ITERS, IPSAMPLER_MIN_SAMPLES,
        IPSAMPLER_GUARD_EARLY_FRAC, IPSAMPLER_GUARD_THRESHOLD,
        IPSAMPLER_LOOP_WINDOW, IPSAMPLER_LOOP_THRESHOLD, IPSAMPLER_LOOP_GUARD_EXCL,
        IPSAMPLER_BRANCHY_PEAK, IPSAMPLER_BRANCHY_MIN_PEAKS,
        SIGN_EXT_FRAC, GUARD_PAGE_SIZE as _PROBE_PAGE_SIZE,
        DOMAIN_TIMING_CV_BRANCHY,
    )
except ImportError:
    from constants import (                                             # type: ignore
        TIER3_DISCRIMINANT_THRESHOLD as TIER3_THRESHOLD,
        CONTEXT_REPLAY_N_RUNS, CONTEXT_REPLAY_N_TEST_ARGS,
        IPSAMPLER_INTERVAL_US, IPSAMPLER_N_ITERS, IPSAMPLER_MIN_SAMPLES,
        IPSAMPLER_GUARD_EARLY_FRAC, IPSAMPLER_GUARD_THRESHOLD,
        IPSAMPLER_LOOP_WINDOW, IPSAMPLER_LOOP_THRESHOLD, IPSAMPLER_LOOP_GUARD_EXCL,
        IPSAMPLER_BRANCHY_PEAK, IPSAMPLER_BRANCHY_MIN_PEAKS,
        SIGN_EXT_FRAC, GUARD_PAGE_SIZE as _PROBE_PAGE_SIZE,
        DOMAIN_TIMING_CV_BRANCHY,
    )

try:
    from .execute    import DLLExecutor, _C_INT64
    from .probe      import ProbeSet, ProbeBuilder, default_probe_set
    from .fingerprint import FingerprintMetrics
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from execute     import DLLExecutor, _C_INT64                      # type: ignore
    from probe       import ProbeSet, ProbeBuilder, default_probe_set  # type: ignore
    from fingerprint import FingerprintMetrics                          # type: ignore


# ── Windows API bootstrap ─────────────────────────────────────────────────────

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

_THREAD_SUSPEND_RESUME = 0x0002
_THREAD_GET_CONTEXT    = 0x0008

# x64 CONTEXT structure (winnt.h)
_CONTEXT_SIZE         = 0x4D0    # 1232 bytes total
_CONTEXT_FLAGS_OFFSET = 0x30     # ContextFlags (DWORD)
_CONTEXT_RIP_OFFSET   = 0xF8     # Rip (ULONG64)
_CONTEXT_CONTROL      = 0x100001 # CONTEXT_AMD64 | CONTEXT_CONTROL

_k32.GetCurrentThreadId.restype  = ctypes.c_ulong
_k32.GetCurrentThreadId.argtypes = []
_k32.OpenThread.restype          = ctypes.c_void_p
_k32.OpenThread.argtypes         = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
_k32.CloseHandle.restype         = ctypes.c_bool
_k32.CloseHandle.argtypes        = [ctypes.c_void_p]

# SuspendThread / GetThreadContext / ResumeThread must be called with the GIL
# HELD (PYFUNCTYPE) so the main thread cannot be inside Python code when we
# suspend it.  With the standard WinDLL (WINFUNCTYPE) the GIL is released
# before each call, creating a window where the background thread loses the
# GIL after ResumeThread and deadlocks waiting to do rip_samples.append().
_SuspendThread = ctypes.PYFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(
    ("SuspendThread", _k32)
)
_GetThreadCtx = ctypes.PYFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)(
    ("GetThreadContext", _k32)
)
_ResumeThread = ctypes.PYFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(
    ("ResumeThread", _k32)
)

# Module-level 16-byte-aligned CONTEXT buffer.
# NOT thread-safe across concurrent IPSampler instances; single-threaded use only.
_CTX_RAW  = (ctypes.c_uint8 * (_CONTEXT_SIZE + 16))()
_CTX_BASE = (ctypes.addressof(_CTX_RAW) + 15) & ~15


def _get_rip(thread_handle: int) -> int | None:
    """Read RIP from thread's x64 CONTEXT.  Called with GIL held (via _GetThreadCtx)."""
    ctypes.c_ulong.from_address(_CTX_BASE + _CONTEXT_FLAGS_OFFSET).value = _CONTEXT_CONTROL
    if not _GetThreadCtx(thread_handle, ctypes.c_void_p(_CTX_BASE)):
        return None
    return ctypes.c_uint64.from_address(_CTX_BASE + _CONTEXT_RIP_OFFSET).value


def _open_self() -> int:
    """Open a suspendable, context-readable handle to the calling thread."""
    tid    = _k32.GetCurrentThreadId()
    handle = _k32.OpenThread(
        _THREAD_SUSPEND_RESUME | _THREAD_GET_CONTEXT, False, tid
    )
    if not handle:
        raise OSError(f"OpenThread failed: err={ctypes.get_last_error()}")
    return handle


def _export_va(executor: DLLExecutor, name: str) -> int | None:
    """Look up the runtime VA of an exported function by name."""
    try:
        fn = getattr(executor._dll, name, None)
        if fn is None:
            return None
        return ctypes.cast(fn, ctypes.c_void_p).value
    except Exception:
        return None


# ── Tier3Result ───────────────────────────────────────────────────────────────

@dataclass
class Tier3Result:
    """
    Output from run_tier3(). All fields are LLM-ready.

    Fields that could not be determined are None — not a classification error,
    just means that specific test lacked sufficient data or didn't apply.
    """
    func_id:             str

    # Purity
    is_pure:             bool | None  # None = stale-init smell / indeterminate
    purity_confidence:   float
    divergence_rate:     float        # fraction of runs that returned a different output

    # Argument sensitivity
    sensitive_args:      list[int]    # 0-indexed arg positions that affect output
    n_args_detected:     int

    # Return type
    ret_bits:            int          # 8 / 16 / 32 / 64
    ret_signed:          bool | None

    # IP histogram
    ip_pattern:          str          # guard / flat / loop / branchy / unknown
    ip_guard_frac:       float        # fraction of in-function samples in first 20%
    ip_samples_total:    int
    ip_histogram:        dict         # hex(VA) → count, top-20

    # Verdict
    discriminant_before: float
    llm_hint:            str

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ── ContextReplay ─────────────────────────────────────────────────────────────

class ContextReplay:
    """
    Repeated-execution analysis using call_batch().

    No hardware debug registers — we just run the function multiple times
    with identical inputs and observe differences in outputs and across arg
    positions.  Surprisingly informative and completely user-mode.
    """

    def __init__(self, executor: DLLExecutor):
        self.ex = executor

    def test_purity(
        self,
        func:        int | str,
        probe_value: int,
        n_runs:      int = CONTEXT_REPLAY_N_RUNS,
    ) -> tuple[bool | None, float, float]:
        """
        Run func(probe_value) n_runs times and compare outputs.

        Returns (is_pure, purity_confidence, divergence_rate).

          True,  1.0, 0.0  — all outputs identical (deterministic)
          False, c,   r    — outputs diverge (reads/modifies external state)
          None,  0.3, 0.0  — all identical but suspicious (zero out for nonzero in)
                             → function likely needs initialisation state
        """
        results = self.ex.call_batch(func, [[probe_value]] * n_runs)
        outputs = [r.retval for r in results if r.retval is not None]
        if len(outputs) < 2:
            return None, 0.0, 1.0

        majority_val, majority_cnt = Counter(outputs).most_common(1)[0]
        divergence_rate = 1.0 - (majority_cnt / len(outputs))

        if len(set(outputs)) == 1:
            # Stale-init smell: nonzero input → always zero output
            if probe_value != 0 and majority_val == 0:
                return None, 0.3, 0.0
            return True, 1.0, 0.0

        return False, round(1.0 - divergence_rate, 3), round(divergence_rate, 3)

    def scan_arg_sensitivity(
        self,
        func:        int | str,
        n_test_args: int        = CONTEXT_REPLAY_N_TEST_ARGS,
        probe_vals:  list[int] | None = None,
    ) -> tuple[list[int], int]:
        """
        For each arg position i: vary arg i while fixing all others at 0.
        Sensitive if the output distribution has variance > 0.

        Returns (sensitive_arg_indices, n_args_detected).
        """
        probe_vals = probe_vals or [0x1, 0x7, 0x3f, 0x100, 0x1000, 0x7fffffff]
        sensitive: list[int] = []

        for i in range(n_test_args):
            probes = []
            for v in probe_vals:
                args = [0] * n_test_args
                args[i] = v
                probes.append(args)
            outputs = [
                r.retval for r in self.ex.call_batch(func, probes)
                if r.retval is not None
            ]
            if len(set(outputs)) > 1:
                sensitive.append(i)

        n_args = (max(sensitive) + 1) if sensitive else 1
        return sensitive, n_args

    @staticmethod
    def infer_ret_type(outputs: list[int]) -> tuple[int, bool | None]:
        """
        Infer return value bit-width and signedness from observed outputs.

        Returns (ret_bits, is_signed).  is_signed=None means indeterminate.
        """
        if not outputs:
            return 64, None

        mask64 = 0xFFFFFFFFFFFFFFFF
        safe   = [v & mask64 for v in outputs]

        if any(v > 0xFFFFFFFF for v in safe):
            bits = 64
        elif any(v > 0xFFFF for v in safe):
            bits = 32
        elif any(v > 0xFF for v in safe):
            bits = 16
        else:
            bits = 8

        # Sign-extension pattern: high 32 bits == 0xFFFFFFFF on some outputs → signed 32-bit
        sign_ext = [v for v in safe if v > 0x7FFFFFFF and (v >> 32) == 0xFFFFFFFF]
        if bits == 32 and len(sign_ext) > len(safe) * 0.10:
            return 32, True
        if bits == 64 and any(v > 0x7FFFFFFFFFFFFFFF for v in safe):
            return 64, True

        return bits, None


# ── IPSampler ─────────────────────────────────────────────────────────────────

class IPSampler:
    """
    Code-path frequency analysis via thread-suspend RIP polling.

    A background thread repeatedly suspends the probe thread, reads RIP, and
    resumes — while the probe thread calls the function in a tight loop.

    GIL safety: ctypes calls (SuspendThread, GetThreadContext, ResumeThread)
    release the Python GIL.  ResumeThread is called before any Python list
    operation, so the probe thread is never left suspended while the background
    thread waits for the GIL.
    """

    def __init__(self, executor: DLLExecutor):
        self.ex = executor

    def sample(
        self,
        func:           int | str,
        arg:            int,
        func_entry_va:  int | None = None,
        func_size_hint: int        = _PROBE_PAGE_SIZE,
        n_iters:        int        = IPSAMPLER_N_ITERS,
        interval_us:    float      = IPSAMPLER_INTERVAL_US,
    ) -> dict[int, int]:
        """
        Run func(arg) n_iters times while sampling RIP every interval_us µs.

        Returns {rip_va: count} filtered to [func_entry_va, func_entry_va + func_size_hint).
        Returns empty dict if < 10 in-function samples were collected (function too fast).
        """
        # Resolve runtime entry VA for filtering
        if func_entry_va is None:
            if isinstance(func, int):
                func_entry_va = func + self.ex.rebase
            else:
                func_entry_va = _export_va(self.ex, func)

        func_end_va = (func_entry_va + func_size_hint) if func_entry_va else None

        rip_samples: list[int] = []
        stop_event = threading.Event()

        try:
            probe_handle = _open_self()
        except OSError:
            return {}

        interval_s = interval_us * 1e-6

        def _poll() -> None:
            while not stop_event.is_set():
                # GIL is held here (Python code).  _SuspendThread / _GetThreadCtx /
                # _ResumeThread are PYFUNCTYPE — they keep the GIL held, guaranteeing
                # the main thread is NOT in Python (it released the GIL for its ctypes
                # DLL call) when suspended.  Avoids the deadlock from WinDLL's GIL release.
                _SuspendThread(probe_handle)
                rip = _get_rip(probe_handle)
                _ResumeThread(probe_handle)
                if rip is not None:
                    rip_samples.append(rip)
                time.sleep(interval_s)

        t = threading.Thread(target=_poll, daemon=True)
        t.start()
        try:
            self.ex.call_batch(func, [[arg]] * n_iters)
        finally:
            stop_event.set()
            t.join(timeout=2.0)
            _k32.CloseHandle(probe_handle)

        # Filter to in-function window
        if func_entry_va and func_end_va:
            in_func = [r for r in rip_samples if func_entry_va <= r < func_end_va]
        else:
            in_func = rip_samples

        if len(in_func) < IPSAMPLER_MIN_SAMPLES:
            return {}

        return dict(Counter(in_func).most_common(50))

    @staticmethod
    def classify_histogram(
        histogram:      dict[int, int],
        func_entry_va:  int,
        func_size_hint: int = _PROBE_PAGE_SIZE,
    ) -> tuple[str, float]:
        """
        Classify code-path shape from the IP histogram.

        Returns (pattern, guard_frac):
          guard   — >60% of samples in first 20% of function → early-exit confirmed
          flat    — uniform distribution → hash / PRNG / arithmetic
          loop    — >50% cluster in a 10% mid-function window → tight inner loop
          branchy — two or more peaks > 15% each → dispatch / FSM
          unknown — < 20 samples or no in-function samples
        """
        if not histogram or sum(histogram.values()) < 20:
            return "unknown", 0.0

        total  = sum(histogram.values())
        lo, hi = func_entry_va, func_entry_va + max(1, func_size_hint)

        rel: list[tuple[float, int]] = [
            ((va - lo) / max(1, func_size_hint), cnt)
            for va, cnt in histogram.items()
            if lo <= va < hi
        ]
        if not rel:
            return "unknown", 0.0

        guard_frac = sum(c for off, c in rel if off < IPSAMPLER_GUARD_EARLY_FRAC) / total

        if guard_frac > IPSAMPLER_GUARD_THRESHOLD:
            return "guard", round(guard_frac, 3)

        # Flat: low coefficient of variation of relative offsets
        offsets = [off for off, cnt in rel for _ in range(cnt)]
        if offsets:
            mean = sum(offsets) / len(offsets)
            var  = sum((o - mean) ** 2 for o in offsets) / len(offsets)
            cv   = (var ** 0.5) / max(mean, 0.001)
            if cv < DOMAIN_TIMING_CV_BRANCHY:
                return "flat", round(guard_frac, 3)

        # Loop: >IPSAMPLER_LOOP_THRESHOLD in a IPSAMPLER_LOOP_WINDOW window
        window = IPSAMPLER_LOOP_WINDOW
        best_cluster = max(
            sum(c for off, c in rel if p <= off < p + window) / total
            for p in (i * 0.05 for i in range(18))
        )
        if best_cluster > IPSAMPLER_LOOP_THRESHOLD and guard_frac < IPSAMPLER_LOOP_GUARD_EXCL:
            return "loop", round(guard_frac, 3)

        # Branchy: IPSAMPLER_BRANCHY_MIN_PEAKS windows each holding > IPSAMPLER_BRANCHY_PEAK
        peaks = sum(
            1 for p in (i * 0.05 for i in range(18))
            if sum(c for off, c in rel if p <= off < p + window) / total > IPSAMPLER_BRANCHY_PEAK
        )
        if peaks >= IPSAMPLER_BRANCHY_MIN_PEAKS:
            return "branchy", round(guard_frac, 3)

        return "unknown", round(guard_frac, 3)


# ── Discriminant gate ─────────────────────────────────────────────────────────

# TIER3_THRESHOLD imported from constants.py above


def _discriminant(m: FingerprintMetrics) -> float:
    return max(m.avalanche_mean, m.entropy_norm, m.sentinel_frac) - 0.5


# ── run_tier3 ─────────────────────────────────────────────────────────────────

def run_tier3(
    executor:  DLLExecutor,
    func:      int | str,
    probe_set: ProbeSet,
    metrics:   FingerprintMetrics,
) -> Tier3Result | None:
    """
    Tier 3 escalation when Tier 1/2 insufficient.

    Returns None immediately if discriminant >= TIER3_THRESHOLD (don't pay the
    cost when the function is already classified with high confidence).

    Sequence:
      1. ContextReplay.test_purity()        — is the function deterministic?
      2. ContextReplay.scan_arg_sensitivity()  — which args actually matter?
      3. ContextReplay.infer_ret_type()     — 32-bit or 64-bit return?
      4. IPSampler.sample() × 2            — code-path histogram
      5. Build Tier3Result with LLM hint
    """
    disc = _discriminant(metrics)
    if disc >= TIER3_THRESHOLD:
        return None

    func_id   = metrics.func_id
    replay    = ContextReplay(executor)
    sampler   = IPSampler(executor)
    probe_val = probe_set.flat[0] if probe_set.flat else 1

    # ── 1. Purity ─────────────────────────────────────────────────────────────
    is_pure, purity_conf, div_rate = replay.test_purity(func, probe_val)

    # ── 2+3. Arg sensitivity + return type (skip if clearly impure) ───────────
    if is_pure is not False:
        sensitive_args, n_args = replay.scan_arg_sensitivity(func)
        io_outputs = [
            r.retval for r in executor.call_batch(func, probe_set.call_args())
            if r.retval is not None
        ]
        ret_bits, ret_signed = ContextReplay.infer_ret_type(io_outputs)
    else:
        # Impure: arg sensitivity scan would be poisoned by side-effect state changes
        sensitive_args, n_args = [0], 1
        ret_bits, ret_signed   = 64, None

    # ── 4. IP sampling ────────────────────────────────────────────────────────
    func_va = (func + executor.rebase) if isinstance(func, int) else _export_va(executor, func)

    hist_a = sampler.sample(func, probe_val,                          func_entry_va=func_va)
    hist_b = sampler.sample(func, probe_set.flat[-1] if len(probe_set.flat) > 1 else probe_val,
                            func_entry_va=func_va)

    # Merge both probe-value histograms
    combined: dict[int, int] = {}
    for h in (hist_a, hist_b):
        for va, cnt in h.items():
            combined[va] = combined.get(va, 0) + cnt

    ip_pattern, ip_guard_frac = IPSampler.classify_histogram(combined, func_va or 0)

    ip_hist_top = {
        hex(va): cnt
        for va, cnt in sorted(combined.items(), key=lambda x: -x[1])[:20]
    }

    # ── 5. LLM hint ───────────────────────────────────────────────────────────
    purity_str = ("pure" if is_pure
                  else "IMPURE" if is_pure is False
                  else "indeterminate")
    hint_parts = [
        f"TIER3({func_id}):",
        f"purity={purity_str}(conf={purity_conf:.2f}, div_rate={div_rate:.2f})",
        f"sensitive_args={sensitive_args} n_args~{n_args}",
        f"ret={ret_bits}bit{'_signed' if ret_signed else ''}",
        f"ip_pattern={ip_pattern}(guard_frac={ip_guard_frac:.2f})",
    ]

    if is_pure is False:
        hint_parts.append(
            "WARNING: function reads or modifies external state — "
            "I/O matching unreliable; LLM should treat outputs as volatile"
        )
    if ip_pattern == "guard":
        hint_parts.append(
            f"IP evidence: {ip_guard_frac:.0%} of execution samples in first "
            f"20% of function body — guard/early-exit path CONFIRMED by direct observation"
        )
    elif ip_pattern == "flat":
        hint_parts.append(
            "IP evidence: uniform RIP distribution — "
            "consistent with hash / PRNG / arithmetic (no dominant branch)"
        )
    elif ip_pattern == "loop":
        hint_parts.append(
            "IP evidence: >50% of samples cluster mid-function — "
            "tight inner loop detected (codec, search, accumulator)"
        )
    elif ip_pattern == "branchy":
        hint_parts.append(
            "IP evidence: multi-modal RIP distribution — "
            "multiple execution paths of comparable weight (dispatch table / FSM)"
        )
    elif ip_pattern == "unknown":
        if sum(combined.values()) == 0:
            hint_parts.append(
                "IP evidence: 0 in-function samples collected — function executes "
                "below ~15us sampling resolution; INFERRED: fast simple scalar "
                "(hash step, bit op, arithmetic) NOT a complex branching function. "
                "Rely on avalanche/entropy/algebraic_degree metrics for classification."
            )
        else:
            hint_parts.append(
                f"IP evidence: {sum(combined.values())} samples collected but no "
                "dominant pattern — code path distribution ambiguous; "
                "treat IP signal as inconclusive."
            )
    if n_args > 1 and len(sensitive_args) > 1:
        hint_parts.append(
            f"Hidden-arg evidence: Ghidra may have shown 1 arg "
            f"but args {sensitive_args} all affect output — re-examine signature"
        )

    return Tier3Result(
        func_id             = func_id,
        is_pure             = is_pure,
        purity_confidence   = round(purity_conf, 3),
        divergence_rate     = round(div_rate, 3),
        sensitive_args      = sensitive_args,
        n_args_detected     = n_args,
        ret_bits            = ret_bits,
        ret_signed          = ret_signed,
        ip_pattern          = ip_pattern,
        ip_guard_frac       = round(ip_guard_frac, 3),
        ip_samples_total    = sum(combined.values()),
        ip_histogram        = ip_hist_top,
        discriminant_before = round(disc, 3),
        llm_hint            = "  ".join(hint_parts),
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Tier 3 behavioral escalation for a stripped DLL function.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--dll",    required=True,  help="Path to the DLL")
    ap.add_argument("--func",   required=True,  help="Export name or Ghidra VA (0x...)")
    ap.add_argument("--code",   default="",     help="Pseudocode file for probe set")
    ap.add_argument("--n-args", type=int, default=1)
    ap.add_argument("--hint",   action="store_true", help="Print only llm_hint")
    ap.add_argument("--force",  action="store_true",
                    help="Run even if discriminant >= threshold (bypass gate)")
    opts = ap.parse_args()

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from dynamic.execute     import DLLExecutor as _Ex
        from dynamic.fingerprint import run as fp_run
        from dynamic.probe       import ProbeBuilder, default_probe_set as _dps
    except ImportError:
        from execute     import DLLExecutor as _Ex           # type: ignore
        from fingerprint import run as fp_run                # type: ignore
        from probe       import ProbeBuilder, default_probe_set as _dps  # type: ignore

    ex   = _Ex(opts.dll)
    func = int(opts.func, 16) if opts.func.startswith("0x") else opts.func
    code = ""
    if opts.code:
        with open(opts.code, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()

    ps      = ProbeBuilder(code).build() if code else _dps(opts.n_args)
    metrics = fp_run(ex, func, pseudocode=code, n_args=opts.n_args)

    if opts.force:
        # Temporarily spoof discriminant below threshold
        metrics.avalanche_mean = 0.0
        metrics.entropy_norm   = 0.0
        metrics.sentinel_frac  = 0.0

    result = run_tier3(ex, func, ps, metrics)

    if result is None:
        print(f"Tier 3 not triggered: discriminant={_discriminant(metrics):.3f} "
              f">= threshold {TIER3_THRESHOLD}. Use --force to override.")
    elif opts.hint:
        print(result.llm_hint)
    else:
        print(result.to_json())
