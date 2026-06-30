"""
dynamic/nano_sim.py — High-density behavioral simulation with discriminating output selection.

For SIMD-vectorized functions where pseudocode is unreliable:
  Phase 1: Run N probes cheaply (SIMD calls are sub-microsecond each)
  Phase 2: Select the maximally discriminating I/O subset for LLM consumption

The discriminating set captures:
  - One example per distinct output value (covers output diversity)
  - Transition boundary points (where output value changes — reveals structure)
  - Stratified magnitude samples (small/medium/large inputs)

This gives the LLM concrete behavioral evidence without flooding it with
redundant I/O pairs. For a primality test, 6 pairs are sufficient:
  f(2)=1 f(4)=0 f(9)=0 f(97)=1 f(100)=0 f(101)=1
— which immediately reveals the prime/composite structure.

Works best for: arithmetic functions, predicates, small-domain functions.
Less useful for: pure hash/PRNG (high-entropy outputs, all distinct → dense sweep
just confirms "every output different" which classify already tells us).
"""
from __future__ import annotations
import math
from dynamic.execute import DLLExecutor, ExecuteResult


# ── Probe strategies ──────────────────────────────────────────────────────────

def _dense_sweep(executor: DLLExecutor, func: int | str,
                 n: int = 2048) -> list[tuple[int, int]]:
    """
    Run n probes over [0, n) — covers small values densely where
    most algorithmic structure is visible (prime patterns, modular arithmetic,
    range checks, etc.).
    """
    probes  = [[i] for i in range(n)]
    results = executor.call_batch(func, probes)
    return [(r.args[0], r.retval)
            for r in results
            if r.retval is not None and r.error is None and r.args]


def _extended_sweep(executor: DLLExecutor, func: int | str) -> list[tuple[int, int]]:
    """
    Extend beyond the dense sweep: logarithmically spaced large values + known
    algorithmic landmarks (primes, powers of 2, Fibonacci, etc.).
    """
    landmarks = [
        # Powers of 2
        2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 65536,
        # Known primes (to reveal prime-sensitive behavior)
        101, 127, 251, 509, 1021, 2039, 4093, 8191, 16381, 65521,
        # Fibonacci numbers
        89, 144, 233, 377, 610, 987, 1597, 2584,
        # Multiples of small primes (composites)
        100, 1000, 10000, 100000,
        # Squares of primes
        121, 169, 289, 361, 529, 841, 961,
        # Negative values (signed behavior detection)
        -1, -2, -3, -100,
    ]
    probes  = [[x] for x in landmarks]
    results = executor.call_batch(func, probes)
    pairs   = [(r.args[0], r.retval)
               for r in results
               if r.retval is not None and r.error is None and r.args]
    return pairs


# ── Discriminating subset selection ──────────────────────────────────────────

def _select_discriminating(pairs: list[tuple[int, int]],
                           n_select: int = 20) -> list[tuple[int, int]]:
    """
    From a large set of (input, output) pairs, select the maximally
    informative subset for LLM consumption.

    Selection strategy (ordered by information value):
    1. One example per distinct output value — covers output diversity
    2. Transition boundary points — where output value changes (reveals structure)
    3. Stratified magnitude samples — small/medium/large inputs

    The selected set is sorted by input for readability.
    """
    if not pairs:
        return []

    selected: list[tuple[int, int]] = []
    seen_set: set[tuple[int, int]]  = set()

    def add(p: tuple[int, int]) -> bool:
        if p not in seen_set and len(selected) < n_select:
            selected.append(p)
            seen_set.add(p)
            return True
        return False

    # 1. One example per distinct output value (smallest input that produces it)
    by_output: dict[int, tuple[int, int]] = {}
    for x, y in sorted(pairs, key=lambda p: abs(p[0])):   # prefer small |x|
        if y not in by_output:
            by_output[y] = (x, y)
    for p in sorted(by_output.values(), key=lambda p: p[0]):
        add(p)

    # 2. Transition boundary points (where consecutive output values differ)
    sorted_pairs = sorted(pairs, key=lambda p: p[0])
    prev_y = sorted_pairs[0][1] if sorted_pairs else None
    for i, (x, y) in enumerate(sorted_pairs[1:], 1):
        if y != prev_y:
            add(sorted_pairs[i - 1])   # last point of previous run
            add((x, y))                 # first point of new run
        prev_y = y

    # 3. Stratified magnitude samples to fill remaining slots
    if len(selected) < n_select and sorted_pairs:
        stride = max(1, len(sorted_pairs) // (n_select - len(selected) + 1))
        for p in sorted_pairs[::stride]:
            if not add(p):
                continue

    return sorted(selected, key=lambda p: p[0])[:n_select]


# ── Main entry point ──────────────────────────────────────────────────────────

def nano_sim(
    executor:  DLLExecutor,
    func:      int | str,
    n_probes:  int = 2048,
    n_display: int = 20,
) -> dict:
    """
    Run high-density behavioral simulation and return maximally discriminating
    I/O pairs for LLM injection.

    Returns dict with:
      pairs       : [(input, output), ...] — n_display most informative pairs
      n_probed    : total probes run
      n_distinct  : distinct output values observed
      is_constant : True if all outputs identical
      llm_hint    : formatted string for direct injection into LLM context
    """
    # Phase 1: dense sweep + extended landmarks
    dense   = _dense_sweep(executor, func, n=n_probes)
    extended = _extended_sweep(executor, func)
    all_pairs = list({(x, y) for x, y in dense + extended})  # deduplicate

    if not all_pairs:
        return {"pairs": [], "n_probed": 0, "n_distinct": 0,
                "is_constant": True, "llm_hint": "NANO_SIM: no valid probes"}

    outputs      = [y for _, y in all_pairs]
    n_distinct   = len(set(outputs))
    is_constant  = n_distinct == 1

    # Phase 2: select discriminating subset
    selected = _select_discriminating(all_pairs, n_select=n_display)

    # Build LLM hint
    io_str = "  ".join(f"f({x})={y}" for x, y in selected)
    if is_constant:
        hint = (f"NANO_SIM ({len(all_pairs)} probes): CONSTANT — always returns "
                f"{outputs[0]}. Function may be a stub or have single-path behavior.")
    elif n_distinct <= 3:
        hint = (f"NANO_SIM ({len(all_pairs)} probes, {n_distinct} distinct outputs — "
                f"likely a predicate/classifier):\n  {io_str}")
    elif n_distinct > len(all_pairs) * 0.8:
        hint = (f"NANO_SIM ({len(all_pairs)} probes, {n_distinct} distinct outputs — "
                f"high output entropy, likely hash/transform):\n  {io_str}")
    else:
        hint = (f"NANO_SIM ({len(all_pairs)} probes, {n_distinct} distinct outputs — "
                f"structured mapping):\n  {io_str}")

    return {
        "pairs":      selected,
        "n_probed":   len(all_pairs),
        "n_distinct": n_distinct,
        "is_constant": is_constant,
        "llm_hint":   hint,
    }


def nano_sim_hint(executor: DLLExecutor, func: int | str,
                  n_probes: int = 2048) -> str:
    """Convenience wrapper — returns just the llm_hint string."""
    return nano_sim(executor, func, n_probes=n_probes)["llm_hint"]


# ── Information-theoretic probe selection ─────────────────────────────────────
# The algebraic degree d of a function (from WHT) means d+1 probes at
# algebraically independent points EXACTLY characterize the function within
# the polynomial hypothesis class (Lagrange interpolation).
#
# For non-polynomial functions: the discriminating sweep approach (above) is
# asymptotically optimal — it finds transition boundaries which correspond to
# the critical inputs where hypothesis classes diverge.
#
# Connection to our WHT:
#   algebraic_degree=1 → 2 probes suffice (linear function)
#   algebraic_degree=2 → 3 probes suffice (quadratic)
#   algebraic_degree=5 → ~6 probes needed
#   high degree → use dense sweep + discriminating selection
#
# The _select_discriminating() function above approximates the
# optimal probe selection by finding transition boundaries,
# which are the inputs where the function's behavior changes —
# equivalent to the "critical inputs" in exact learning theory.


def nano_sim_optimal(executor: DLLExecutor, func: int | str,
                     algebraic_degree: int = -1,
                     n_display: int = 20) -> dict:
    """
    Run nano-simulation with probe density scaled to algebraic complexity.

    If algebraic_degree is known (from fingerprint.py WHT):
    - Low degree (1-2): 64 probes is plenty, high confidence
    - Medium degree (3-5): 512 probes
    - High degree (6+): 2048+ probes
    - Unknown (-1): 2048 probes (safe default)
    """
    if algebraic_degree == 1:
        n_probes = 64     # linear: 64 points over-determines, perfect confidence
    elif algebraic_degree == 2:
        n_probes = 256
    elif algebraic_degree <= 5:
        n_probes = 512
    else:
        n_probes = 2048   # high complexity: dense sweep

    return nano_sim(executor, func, n_probes=n_probes, n_display=n_display)
