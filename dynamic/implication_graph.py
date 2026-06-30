"""
dynamic/implication_graph.py — Constraint Implication Graph for Init Spec Compression

PURPOSE:
  Given constraints C₁..Cₙ from pcode_sym runs across N functions,
  find the MINIMUM BASIS: the smallest set of independent constraints
  from which all others follow by logical implication.

  This is the Shannon source-coding theorem for binary init specs:
    min_description_length(init_spec) = |minimum_basis|
    redundancy = (N - |minimum_basis|) / N

WHY THIS MATTERS FOR LLM-OPTIMAL BINARY EXPLORATION:
  An LLM interpreting binary functions needs to reason about global init state.
  Every independent fact it needs to process costs inference budget (tokens/attention).
  If constraint A implies B implies C, the LLM only needs to be told A.
  The minimum basis = the minimum inference budget for full understanding.

  Optimal discriminant = projection that maximally separates semantic classes
  with minimum inference cost. This module finds that minimum for the init spec.

THEORY:
  - Constraint implication: Cᵢ → Cⱼ iff ¬(Cᵢ → Cⱼ) is UNSAT (Z3 check)
  - Mutual implication (Cᵢ ↔ Cⱼ) → equivalent constraints (same information)
  - SCCs in implication graph = equivalence classes
  - DAG of SCCs → partial order of constraint strength
  - Minimum basis = sources of the DAG (no incoming edges from non-equivalent nodes)

  Redundancy ratio = 1 - |basis| / |total|
  → 0 = all constraints independent (maximum complexity init spec)
  → 1 = all constraints implied by one (minimum complexity, one primitive fact)

CONNECTION TO MATHEMATICAL THEORIES:
  - Shannon entropy: min bits to encode a random variable = -Σ pᵢ log pᵢ
  - Kolmogorov complexity: min program length to generate a string
  - Our minimum basis length: min facts to specify the init state
  All three are measures of "intrinsic information content" of different objects.

  The constraint lattice (partial order by implication) maps to:
  - Galois connection between observable behavior and init state
  - Birkhoff's representation: every finite distributive lattice = J(poset)
    where J = join-irreducible elements = our minimum basis
"""
from __future__ import annotations
import sys
from dataclasses import dataclass, field
from collections import defaultdict
import time

try:
    import claripy
    import networkx as nx
    _HAS_DEPS = True
except ImportError:
    _HAS_DEPS = False


@dataclass
class ConstraintNode:
    """One constraint from one function's pcode_sym run."""
    formula:      object    # claripy formula
    fn_name:      str
    cbranch_va:   int
    taken:        bool
    global_vars:  frozenset[str]  # which BVS names appear in this constraint
    is_ambiguous: bool     # CBRANCH_AMBIGUOUS — both branches satisfiable


@dataclass
class ImplicationResult:
    """Result of implication graph analysis."""
    n_constraints:     int
    n_unique_formulas: int      # after deduplication
    n_equivalence_classes: int  # SCCs
    minimum_basis:     list[ConstraintNode]  # irredundant generators
    redundancy:        float    # 1 - |basis| / |unique|
    implications:      list[tuple[int,int]]  # (i→j) edges in the graph
    scc_sizes:         list[int]
    # New discriminant: which global variables are "load-bearing"
    # (appear in minimum basis constraints vs. implied constraints only)
    load_bearing_globals: list[str]
    implied_globals:      list[str]
    # Minimum description length estimate
    mdl_bits:          float    # log2(|basis|) if basis is the optimal code
    # T_field_type: semantic type per global variable (from constraint shape)
    global_field_types: dict = field(default_factory=dict)  # {var_name: dominant_type}


def _canonical_bvs_name(bvs_name: str) -> tuple[str, int]:
    """
    Parse claripy's internal BVS name format: 'global_0xADDR_INSTANCE_BITS'
    Returns (canonical_name, bit_width).

    Example: 'global_0x20ca66748_5_64' → ('g_0x20ca66748', 64)
             'field_0x1000_0x18_3_64'  → ('f_0x1000_0x18', 64)

    WHY THIS MATTERS: claripy appends _INSTANCE_BITS to every BVS, making the
    same global address appear as different variables in different function runs.
    Cross-function implication checking requires stripping this suffix so that
    constraints from different functions referencing the same global address
    share variable names. Without this, variable intersection is always empty
    and zero implications are ever found across functions.
    """
    parts = bvs_name.rsplit('_', 2)  # split off last two segments
    if len(parts) == 3:
        base, instance, bits = parts
        try:
            bit_width = int(bits)
            int(instance)  # verify it's a number
            if base.startswith('global_'):
                addr = base[len('global_'):]
                return f'g_{addr}', bit_width
            elif base.startswith('field_'):
                return f'f_{base[len("field_"):]}', bit_width
            else:
                return base, bit_width
        except ValueError:
            pass
    return bvs_name, 64  # fallback


def canonicalize_formula(formula: object) -> object:
    """
    Substitute all BVS variables in formula with canonical versions.
    'global_0x20ca66748_5_64' (claripy internal name) → 'g_0x20ca66748' of width 64.

    Uses claripy's real API (verified from source):
      - replace_dict(expr, {hash: new_expr}) for substitution
      - leaf_operation to collect BVS leaf objects with their hashes
      - BVS(..., explicit_name=True) to create canonical BVS with stable hash

    WHY explicit_name=True: claripy appends _INSTANCE_BITS to every BVS name
    unless explicit_name=True is given. With explicit_name=True, the same
    (name, bits) pair always gives the same hash — enabling cross-function comparison.
    """
    if not _HAS_DEPS:
        return formula
    try:
        from claripy.algorithm.replace import replace_dict as _replace_dict
        if not hasattr(formula, 'variables') or not formula.variables:
            return formula

        # Step 1: collect all BVS leaf objects from the formula tree
        bvs_by_name: dict[str, object] = {}

        def _collect_bvs(leaf):
            if hasattr(leaf, 'op') and leaf.op == 'BVS':
                name_in_formula = leaf.args[0]  # the internal name string
                bvs_by_name[name_in_formula] = leaf
            return leaf

        _replace_dict(formula, {}, leaf_operation=_collect_bvs)

        if not bvs_by_name:
            return formula

        # Step 2: build replacement dict {old_hash: canonical_bvs}
        replacements: dict[int, object] = {}
        for internal_name, old_bvs in bvs_by_name.items():
            canon_name, bits = _canonical_bvs_name(internal_name)
            if canon_name != internal_name:
                # explicit_name=True: no _INSTANCE_BITS suffix → stable hash
                canon_bvs = claripy.BVS(canon_name, bits, explicit_name=True)
                replacements[old_bvs.hash()] = canon_bvs

        if not replacements:
            return formula

        # Step 3: apply substitution
        return _replace_dict(formula, replacements)
    except Exception:
        return formula


def extract_constraint_nodes(
    fn_name:      str,
    constraints:  list,   # list of GlobalConstraint from ExecResult
    silent_guesses: list[str],
    canonicalize: bool = True,
) -> list[ConstraintNode]:
    """
    Convert pcode_sym ExecResult constraints to ConstraintNode list.

    canonicalize=True (default): strip claripy's internal _INSTANCE_BITS suffix
    from BVS names so cross-function constraints over the same global address
    share variable names and can be compared by implication checking.
    """
    nodes = []
    for c in constraints:
        try:
            formula = c.constraint
            if formula is None or not hasattr(formula, 'variables'):
                continue
            if canonicalize:
                formula = canonicalize_formula(formula)
            vars_in = frozenset(str(v) for v in formula.variables)
            if not vars_in:
                continue
            nodes.append(ConstraintNode(
                formula=formula,
                fn_name=fn_name,
                cbranch_va=0,
                taken=c.branch_taken,
                global_vars=vars_in,
                is_ambiguous=any('AMBIGUOUS' in g for g in silent_guesses),
            ))
        except Exception:
            pass
    return nodes


# ── T_field_type: semantic type inference from constraint shape ───────────────
# From empirical probe of claripy AST (2026-06-21, verified against real pcode_sym output):
#   cond.op     n_bvs  n_bvv_zero  → type
#   __eq__      1      1           → NULL_CHECK (pointer: checked against 0)
#   __eq__      1      0           → ENUM (checked against specific constant ≠ 0)
#   __ne__      1      any         → EXCLUSION (≠ constant, state machine guard)
#   ULT,UGT     2      0           → PAIR (two globals compared: ring buffer read<write)
#   ULT,ULE     1      0           → RANGE_UPPER (bounded count/size: x < const)
#   UGE,UGT     1      1           → NONNEG (unsigned ≥ 0: size/counter)
#   SGT,SGE...  1      any         → SIGNED (signed range: version number, offset)
#   __and__     any    any         → FLAGS (bitmask test)
# Composite patterns (And/Or of above) → COMPOSITE

FIELD_TYPES = ('POINTER', 'ENUM', 'EXCLUSION', 'RING_BUFFER', 'RANGE', 'SIZE',
               'SIGNED', 'FLAGS', 'COMPOSITE', 'UNKNOWN')


def classify_constraint_field_type(formula: object) -> str:
    """
    Given a canonicalized constraint formula from pcode_sym,
    infer the semantic type of the global(s) it constrains.

    Returns one of FIELD_TYPES.
    """
    if not _HAS_DEPS:
        return 'UNKNOWN'
    try:
        # Our constraints are If(cond, BVV(1,8), BVV(0,8))
        if (hasattr(formula, 'op') and formula.op == 'If'
                and len(formula.args) == 3):
            cond = formula.args[0]
        elif hasattr(formula, 'op'):
            cond = formula  # already a Bool condition
        else:
            return 'UNKNOWN'

        op = cond.op
        args = cond.args
        n_bvs = sum(1 for a in args if hasattr(a, 'op') and a.op == 'BVS')
        n_bvv = sum(1 for a in args if hasattr(a, 'op') and a.op == 'BVV')
        n_bvv_zero = sum(1 for a in args
                         if hasattr(a, 'op') and a.op == 'BVV' and a.args[0] == 0)

        if op == '__eq__':
            if n_bvs == 1 and n_bvv_zero == 1:
                return 'POINTER'      # checked against NULL
            if n_bvs == 1 and n_bvv >= 1:
                return 'ENUM'         # checked against specific constant
            if n_bvs == 2:
                return 'RING_BUFFER'  # two globals equal (sync check)

        elif op == '__ne__':
            if n_bvs == 2:
                return 'RING_BUFFER'  # two globals differ (non-empty check)
            return 'EXCLUSION'        # ≠ constant guard

        elif op in ('ULT', 'ULE'):
            if n_bvs == 2:
                return 'RING_BUFFER'  # read < write (buffer has data)
            if n_bvv_zero == 0 and n_bvv >= 1:
                return 'RANGE'        # x < const (bounded counter)

        elif op in ('UGT', 'UGE'):
            if n_bvs == 2:
                return 'RING_BUFFER'
            if n_bvv_zero >= 1:
                return 'SIZE'         # x >= 0 → unsigned count/size
            return 'RANGE'

        elif op in ('SGT', 'SGE', 'SLT', 'SLE'):
            return 'SIGNED'           # signed comparison → version, offset

        elif op in ('__and__', 'And'):
            return 'FLAGS'            # bitmask

        elif op in ('Or', '__or__', 'And'):
            return 'COMPOSITE'

    except Exception:
        pass
    return 'UNKNOWN'


def classify_global_types(nodes: list[ConstraintNode]) -> dict[str, "Counter"]:
    """
    For each canonical global variable name, count how many constraints
    of each field type reference it.
    Returns {var_name: Counter({type: count})}
    """
    from collections import Counter as _Counter
    result: dict = defaultdict(_Counter)
    for node in nodes:
        ftype = classify_constraint_field_type(node.formula)
        for var in node.global_vars:
            result[var][ftype] += 1
    return dict(result)


def dominant_field_type(type_counter: Counter) -> str:
    """Return the most common field type, excluding UNKNOWN."""
    filtered = {k: v for k, v in type_counter.items() if k != 'UNKNOWN'}
    if not filtered:
        return 'UNKNOWN'
    return max(filtered, key=filtered.get)


def check_implication(ci: object, cj: object,
                       solver_timeout_ms: int = 3000) -> bool:
    """
    Does ci logically imply cj?
    Uses Z3: ci → cj is valid iff ¬(ci → cj) is UNSAT
    ¬(ci → cj) = ci ∧ ¬cj

    Returns True if ci → cj (implication holds).
    Returns False if not implied or timeout.
    """
    if not _HAS_DEPS:
        return False
    try:
        s = claripy.Solver()
        s.timeout = solver_timeout_ms
        # ci ∧ ¬cj — if UNSAT, then ci → cj
        # First convert boolean BVs to proper booleans
        def to_bool(f):
            # claripy Bool: .length is None.  claripy BV: .length is an int.
            # BV8 from pcode_sym (If(cond, BVV(1,8), BVV(0,8))): length=8 → convert.
            # Bool (UGT, ULT, ==): length=None → use directly.
            length = getattr(f, 'length', None)
            if length is not None and length > 1:
                return f != claripy.BVV(0, length)
            return f
        ci_bool = to_bool(ci)
        cj_bool = to_bool(cj)
        s.add(ci_bool)
        s.add(claripy.Not(cj_bool))
        return not s.satisfiable()
    except Exception:
        return False


def build_implication_graph(
    nodes:          list[ConstraintNode],
    max_pairs:      int = 500,
    timeout_per_ms: int = 2000,
    verbose:        bool = False,
) -> ImplicationResult:
    """
    Build the constraint implication graph and find the minimum basis.

    For efficiency: only check implications between constraints that share
    at least one global variable (disjoint-variable constraints can't imply each other).
    """
    if not _HAS_DEPS:
        raise ImportError("pip install claripy networkx")

    # Deduplicate by formula string (same formula from different functions = same constraint)
    seen: dict[str, ConstraintNode] = {}
    for n in nodes:
        key = str(n.formula)
        if key not in seen:
            seen[key] = n
        # else: keep first occurrence
    unique = list(seen.values())
    n_unique = len(unique)

    if verbose:
        print(f"  [{n_unique} unique constraints from {len(nodes)} total]",
              file=sys.stderr, flush=True)

    if n_unique == 0:
        return ImplicationResult(
            n_constraints=0, n_unique_formulas=0, n_equivalence_classes=0,
            minimum_basis=[], redundancy=0.0, implications=[],
            scc_sizes=[], load_bearing_globals=[], implied_globals=[], mdl_bits=0.0)

    # Build implication graph: only check pairs sharing global variables
    G = nx.DiGraph()
    G.add_nodes_from(range(n_unique))

    pairs_checked = 0
    t0 = time.perf_counter()

    for i in range(n_unique):
        for j in range(n_unique):
            if i == j:
                continue
            # Only check if they share at least one global variable
            if not (unique[i].global_vars & unique[j].global_vars):
                continue
            if pairs_checked >= max_pairs:
                if verbose:
                    print(f"  [implication] max_pairs={max_pairs} reached",
                          file=sys.stderr, flush=True)
                break
            implies = check_implication(unique[i].formula, unique[j].formula,
                                         timeout_per_ms)
            pairs_checked += 1
            if implies:
                G.add_edge(i, j)
                if verbose:
                    print(f"  [{i}]→[{j}]: {str(unique[i].formula)[:40]} "
                          f"⊨ {str(unique[j].formula)[:40]}", file=sys.stderr, flush=True)
        else:
            continue
        break

    elapsed = time.perf_counter() - t0
    if verbose:
        print(f"  [{pairs_checked} pairs checked in {elapsed:.1f}s]",
              file=sys.stderr, flush=True)

    # Find SCCs (equivalence classes — mutually implying constraints)
    sccs = list(nx.strongly_connected_components(G))
    scc_sizes = sorted([len(s) for s in sccs], reverse=True)

    # Build condensation DAG
    condensation = nx.condensation(G)

    # Minimum basis = sources in condensation DAG (no predecessors)
    # Each source SCC contributes one representative to the basis
    basis_nodes = []
    for scc_id in condensation.nodes():
        if condensation.in_degree(scc_id) == 0:
            # Pick lowest-index member of this SCC as representative
            scc_members = condensation.nodes[scc_id]['members']
            rep = min(scc_members)
            basis_nodes.append(unique[rep])

    redundancy = 1 - len(basis_nodes) / n_unique if n_unique > 0 else 0
    import math
    mdl_bits = math.log2(len(basis_nodes)) if len(basis_nodes) > 1 else 0

    # Load-bearing globals: appear in basis constraints
    # Implied globals: ONLY appear in implied (non-basis) constraints
    basis_vars = set()
    for n in basis_nodes:
        basis_vars |= n.global_vars
    all_vars = set()
    for n in unique:
        all_vars |= n.global_vars
    implied_vars = all_vars - basis_vars

    implications = list(G.edges())

    # T_field_type: classify each global variable's semantic type
    global_type_counts = classify_global_types(nodes)
    global_field_types = {var: dominant_field_type(ctr)
                          for var, ctr in global_type_counts.items()}

    return ImplicationResult(
        n_constraints=len(nodes),
        n_unique_formulas=n_unique,
        n_equivalence_classes=len(sccs),
        minimum_basis=basis_nodes,
        redundancy=redundancy,
        implications=implications,
        scc_sizes=scc_sizes,
        load_bearing_globals=sorted(basis_vars),
        implied_globals=sorted(implied_vars),
        mdl_bits=mdl_bits,
        global_field_types=global_field_types,
    )


def print_implication_result(r: ImplicationResult, verbose: bool = False) -> None:
    print(f"\n{'='*55}")
    print(f"IMPLICATION GRAPH ANALYSIS")
    print(f"  {r.n_constraints} constraints → {r.n_unique_formulas} unique")
    print(f"  {r.n_equivalence_classes} equivalence classes (SCCs)")
    print(f"  Minimum basis: {len(r.minimum_basis)} constraints")
    print(f"  Redundancy: {r.redundancy:.0%}  "
          f"MDL: {r.mdl_bits:.1f} bits")
    print(f"  Implications found: {len(r.implications)}")
    if r.scc_sizes and r.scc_sizes[0] > 1:
        print(f"  Largest equivalence class: {r.scc_sizes[0]} constraints "
              f"(all carry same information)")
    print(f"\n  Load-bearing globals ({len(r.load_bearing_globals)}):")
    for g in r.load_bearing_globals[:8]:
        print(f"    {g}")
    if r.implied_globals:
        print(f"\n  Implied globals ({len(r.implied_globals)} — "
              f"inferrable from load-bearing):")
        for g in r.implied_globals[:6]:
            print(f"    {g}")
    # T_field_type summary
    if r.global_field_types:
        from collections import Counter as _Counter
        type_summary = _Counter(r.global_field_types.values())
        print(f"\n  T_field_type distribution:")
        for ftype, cnt in sorted(type_summary.items(), key=lambda x: -x[1]):
            pct = cnt / len(r.global_field_types)
            print(f"    {ftype:<14}: {cnt:4d} globals ({pct:.0%})")
        # Show sample of each type
        by_type: dict = {}
        for var, ftype in r.global_field_types.items():
            by_type.setdefault(ftype, []).append(var)
        print(f"  Samples by type:")
        for ftype in ('POINTER', 'RING_BUFFER', 'ENUM', 'RANGE', 'SIZE', 'SIGNED'):
            if ftype in by_type:
                sample = by_type[ftype][0]
                print(f"    {ftype:<14}: {sample}")

    if verbose and r.minimum_basis:
        print(f"\n  Minimum basis constraints:")
        for i, n in enumerate(r.minimum_basis[:6]):
            print(f"    [{i}] fn={n.fn_name}  "
                  f"formula={str(n.formula)[:70]}")


if __name__ == "__main__":
    # Quick test: build two formulas where A → B
    if not _HAS_DEPS:
        print("pip install claripy networkx"); sys.exit(1)

    g = claripy.BVS('global_0x1000', 64)
    h = claripy.BVS('global_0x1008', 64)

    # A: g > 100   B: g > 50   → A implies B (if g>100 then g>50)
    A = claripy.UGT(g, claripy.BVV(100, 64))
    B = claripy.UGT(g, claripy.BVV(50, 64))
    # C: h != 0    — independent (different variable)
    C = h != claripy.BVV(0, 64)
    # D: g > 0     — implied by both A and B
    D = claripy.UGT(g, claripy.BVV(0, 64))

    from dynamic.pcode_sym import GlobalConstraint
    nodes = [
        ConstraintNode(A, 'fn_a', 0, True, frozenset(['global_0x1000']), False),
        ConstraintNode(B, 'fn_b', 0, True, frozenset(['global_0x1000']), True),
        ConstraintNode(C, 'fn_c', 0, True, frozenset(['global_0x1008']), True),
        ConstraintNode(D, 'fn_d', 0, True, frozenset(['global_0x1000']), True),
    ]

    print("Test: A(g>100), B(g>50), C(h!=0), D(g>0)")
    print("Expected: A→B, A→D, B→D (A is strongest on g, C is independent)")
    r = build_implication_graph(nodes, verbose=True)
    print_implication_result(r, verbose=True)
    print("\nExpected minimum basis: {A, C}  (A implies B and D; C is independent)")
    assert len(r.minimum_basis) == 2, f"expected 2, got {len(r.minimum_basis)}"
    print("TEST PASSED")
