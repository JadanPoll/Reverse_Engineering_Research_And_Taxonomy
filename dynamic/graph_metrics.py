"""
dynamic/graph_metrics.py — Call graph topology metrics for function fingerprinting.

Computes genuinely orthogonal signals that are NOT derivable from I/O behavior
or pseudocode content: k-core membership, betweenness centrality, graph rank.

These capture RELATIONAL position in the call network — a dimension none of the
other analysis layers can provide.

Signals
-------
k_core       : int   — k-core number. High = dense algorithm core. Low = periphery/CRT.
               Functions in the max k-core are the structural heart of the binary.
               Noise functions (CRT, utilities) reliably have lower k-core numbers
               because they have few algorithm-meaningful connections.

betweenness  : float — fraction of shortest paths (seed→leaf) passing through this node.
               High betweenness = bridge function; everything flows through it.
               Use as sorting key: present high-betweenness functions first to the LLM.

in_degree    : int   — number of distinct callers (fan-in). Already in func_info as
               caller_count but stored here for graph consistency.

out_degree   : int   — number of distinct callees (fan-out).

graph_rank   : float — composite signal: betweenness × log(size+1) / (in_degree+1).
               High = central + complex + specific (not called everywhere).
               Low  = peripheral OR trivial OR utility.
               Primary sort key for LLM presentation order.

Algorithm notes
---------------
k-core: O(m) via iterative degree-peeling. No external dependencies.
Betweenness: Brandes' algorithm, O(VE) for unweighted graphs.
  For our graph sizes (40-300 nodes, <500 edges): completes in milliseconds.
  We use directed betweenness — path from seed to algorithm leaf matters.

Usage
-----
As a post-walk pass in ghidra_dump_calltree.py:
    from graph_metrics import annotate_calltree
    annotate_calltree(functions)   # mutates in place

As standalone CLI:
    py -3.13 re_toolkit/dynamic/graph_metrics.py calltree.json
    py -3.13 re_toolkit/dynamic/graph_metrics.py calltree.json --top 10
"""
from __future__ import annotations
import json, sys, os, math, argparse
from collections import defaultdict, deque, Counter


# ── K-core decomposition ──────────────────────────────────────────────────────

def _k_core_numbers(adj_undirected: dict[str, set[str]]) -> dict[str, int]:
    """
    Compute k-core number for each node using degree-peeling.
    k-core number = largest k such that the node remains in the k-core subgraph.

    A node's k-core number tells you how "deep" it sits in the dense core of
    the network. Periphery nodes (degree 0-1) get k=0 or k=1.
    Dense algorithm clusters get high k.

    O(m) — linear in edge count.
    """
    degree = {v: len(neighbors) for v, neighbors in adj_undirected.items()}
    nodes = list(degree.keys())
    core = dict(degree)   # will be refined to core number

    # Sort by degree ascending — peel from lowest degree first
    order = sorted(nodes, key=lambda v: degree[v])

    for v in order:
        for u in adj_undirected.get(v, set()):
            if core[u] > core[v]:
                core[u] -= 1
        # core[v] is now finalized as its k-core number
    return core


# ── Betweenness centrality (Brandes' algorithm) ───────────────────────────────

def _betweenness_centrality(
    nodes: list[str],
    adj: dict[str, list[str]],   # directed adjacency
) -> dict[str, float]:
    """
    Directed betweenness centrality using Brandes' algorithm.
    Returns normalized scores in [0, 1].

    For our call graphs: source = seed functions, all nodes reachable.
    We run from ALL nodes as sources (standard normalization).
    O(VE) — fast for our graph sizes.
    """
    bet = {v: 0.0 for v in nodes}
    node_set = set(nodes)

    for s in nodes:
        # BFS to find shortest paths
        stack = []
        pred: dict[str, list[str]] = {v: [] for v in nodes}
        sigma = {v: 0.0 for v in nodes}
        dist  = {v: -1   for v in nodes}
        sigma[s] = 1.0
        dist[s]  = 0
        q = deque([s])

        while q:
            v = q.popleft()
            stack.append(v)
            for w in adj.get(v, []):
                if w not in node_set:
                    continue
                if dist[w] < 0:
                    q.append(w)
                    dist[w] = dist[v] + 1
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)

        # Back-propagation
        delta = {v: 0.0 for v in nodes}
        while stack:
            w = stack.pop()
            for v in pred[w]:
                if sigma[w] > 0:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                bet[w] += delta[w]

    # Normalize: divide by (n-1)(n-2) for directed graphs
    n = len(nodes)
    if n > 2:
        norm = 1.0 / ((n - 1) * (n - 2))
        for v in bet:
            bet[v] *= norm

    return bet


# ── Weakly Connected Components ───────────────────────────────────────────────

def _find_wccs(adj_undirected: dict[str, set[str]]) -> list[set[str]]:
    """
    Find all weakly connected components via BFS on the undirected call graph.
    Returns components sorted largest-first.

    A WCC is a maximal set of functions that can reach each other via call edges
    in EITHER direction (caller→callee or callee→caller).  Disconnected WCCs are
    the structural "islands" — groups of functions with no call path between them.

    Key insight: a large dense WCC that is NOT reachable from any named export is
    not dead code — it's likely a major implementation subsystem (interpreter core,
    crypto engine, renderer) that is only entry-accessible via indirect dispatch.
    """
    visited: set[str] = set()
    components: list[set[str]] = []
    for start in adj_undirected:
        if start in visited:
            continue
        component: set[str] = set()
        queue = deque([start])
        while queue:
            v = queue.popleft()
            if v in visited:
                continue
            visited.add(v)
            component.add(v)
            for w in adj_undirected.get(v, set()):
                if w not in visited:
                    queue.append(w)
        components.append(component)
    return sorted(components, key=len, reverse=True)


def _local_clustering_all(adj_undirected: dict[str, set[str]]) -> dict[str, float]:
    """
    Local clustering coefficient for every node.

    cc(v) = (edges between v's neighbors) / C(deg(v), 2)

    Interpretation:
      cc ≈ 1.0 → tightly interconnected cluster (every neighbor knows every other)
      cc ≈ 0.0 → v sits between groups that don't talk to each other (bridge node)

    High local clustering + disconnected from exports → implementation cluster
    Low local clustering + high betweenness → architectural bridge node
    High local clustering + reachable from exports → API-adjacent subsystem

    This is the LOCAL DENSITY signal the user identified as orthogonal to k-core
    and betweenness. It captures the density of the IMMEDIATE neighborhood,
    not the global graph position.
    """
    result: dict[str, float] = {}
    for v, neighbors in adj_undirected.items():
        k = len(neighbors)
        if k < 2:
            result[v] = 0.0
            continue
        # Count undirected edges between neighbors
        edges = 0
        nb_set = neighbors
        for u in nb_set:
            for w in adj_undirected.get(u, set()):
                if w in nb_set and w > u:   # count each pair once
                    edges += 1
        result[v] = (2 * edges) / (k * (k - 1))
    return result


def _export_distances(
    seed_vas: set[str],
    adj: dict[str, list[str]],
    va_set: set[str],
) -> dict[str, int]:
    """
    BFS forward from named exports: distance[v] = hops from nearest seed to v.
    -1 = unreachable from any seed (in disconnected component).

    Interpretation:
      0     → IS a named export (API surface)
      1–2   → API-adjacent (thin wrapper, direct helper)
      3–6   → implementation layer (typical algo/subsystem function)
      7+    → deep implementation (hot loop, crypto primitive, interpreter inner loop)
      -1    → disconnected (no static path from any named export)

    Together with local_clustering and component_size this gives a 3D position
    for every function in the binary — useful for prioritizing analysis targets.
    """
    dist: dict[str, int] = {v: -1 for v in va_set}
    queue: deque[str] = deque()
    for s in seed_vas:
        if s in va_set and dist[s] == -1:
            dist[s] = 0
            queue.append(s)
    while queue:
        v = queue.popleft()
        for w in adj.get(v, []):
            if w in va_set and dist[w] == -1:
                dist[w] = dist[v] + 1
                queue.append(w)
    return dist


def _classify_component(
    nodes: set[str],
    adj_undirected: dict[str, set[str]],
    k_cores: dict[str, int],
    seed_reachable: set[str],
    fn_names: dict[str, str],
) -> str:
    """
    Classify a WCC into a structural role.  General — no domain knowledge.

    Labels are structural properties, not interpretations:
      SINGLETON          single node, no edges
      TIGHT_CLUSTER      small (<=30), high density (>0.1)
      CALL_CHAIN         low average degree (<1.5) — mostly linear
      DEEP_IMPL_CORE     large, moderate density, high max k-core — likely interpreter/engine
      IMPLEMENTATION_ISLAND  medium, disconnected, meaningful edges
      MIXED_CLUSTER      doesn't fit above patterns
    """
    n = len(nodes)
    if n == 1:
        return "SINGLETON"

    edges = sum(len(adj_undirected.get(v, set()) & nodes) for v in nodes) // 2
    density  = 2 * edges / (n * (n - 1)) if n > 1 else 0.0
    max_k    = max((k_cores.get(v, 0) for v in nodes), default=0)
    avg_deg  = 2 * edges / n if n > 0 else 0
    is_named = any(not fn_names.get(v, "FUN_").startswith("FUN_") for v in nodes)

    if n >= 50 and max_k >= 3:
        return "DEEP_IMPL_CORE"    # large + dense core = interpreter/engine/renderer
    if density > 0.10 and n <= 30:
        return "TIGHT_CLUSTER"     # small cohesive subsystem
    if avg_deg < 1.5:
        return "CALL_CHAIN"        # mostly linear call sequences
    if n >= 10:
        return "IMPLEMENTATION_ISLAND"
    return "MIXED_CLUSTER"


def analyze_components(
    functions: list[dict],
    seed_vas: set[str] | None = None,
) -> list[dict]:
    """
    Full WCC analysis: classify every disconnected component and compute
    per-function local density + export distance metrics.

    Returns list of component dicts sorted by size (largest first).
    Each dict: {id, size, density, max_k_core, role, reachable_from_seeds,
                member_vas, top_hub_va, top_hub_name, avg_local_clustering}
    """
    va_set   = {f["va"] for f in functions}
    fn_names = {f["va"]: f.get("name", "") for f in functions}

    # Build adjacency structures
    adj:   dict[str, list[str]]  = {f["va"]: [] for f in functions}
    adj_u: dict[str, set[str]]   = {f["va"]: set() for f in functions}
    for f in functions:
        for dst in f.get("called_vas", []):
            if dst in va_set:
                adj[f["va"]].append(dst)
                adj_u[f["va"]].add(dst)
                adj_u[dst].add(f["va"])

    # Structural metrics needed for classification
    k_cores   = _k_core_numbers(adj_u)
    local_cc  = _local_clustering_all(adj_u)
    seed_set  = (seed_vas or set()) & va_set
    reachable = _seed_reachable(seed_set, adj) if seed_set else set()
    ex_dist   = _export_distances(seed_set, adj, va_set) if seed_set else {v: -1 for v in va_set}

    # Compute betweenness within each large component (skip tiny ones)
    wccs     = _find_wccs(adj_u)
    results  = []
    for cid, component in enumerate(wccs):
        n     = len(component)
        edges = sum(len(adj_u.get(v, set()) & component) for v in component) // 2
        density = 2 * edges / (n * (n - 1)) if n > 1 else 0.0
        max_k   = max((k_cores.get(v, 0) for v in component), default=0)
        in_reach = any(v in reachable for v in component)
        role    = _classify_component(component, adj_u, k_cores, reachable, fn_names)

        avg_cc  = (sum(local_cc.get(v, 0) for v in component) / n) if n else 0.0

        # Find top hub within component by in-degree + k-core
        top_hub = max(component,
                      key=lambda v: (k_cores.get(v, 0),
                                     len(adj_u.get(v, set()) & component)),
                      default=None)

        results.append({
            "id":                   cid,
            "size":                 n,
            "edge_count":           edges,
            "density":              round(density, 4),
            "max_k_core":           max_k,
            "role":                 role,
            "reachable_from_seeds": in_reach,
            "avg_local_clustering": round(avg_cc, 4),
            "member_vas":           component,
            "top_hub_va":           top_hub,
            "top_hub_name":         fn_names.get(top_hub, "") if top_hub else "",
        })

    # Annotate each function with its component info + local density + export dist
    va_to_comp = {}
    for comp in results:
        for va in comp["member_vas"]:
            va_to_comp[va] = comp

    for f in functions:
        comp = va_to_comp.get(f["va"], {})
        f["component_id"]           = comp.get("id", -1)
        f["component_size"]         = comp.get("size", 1)
        f["component_density"]      = comp.get("density", 0.0)
        f["component_role"]         = comp.get("role", "SINGLETON")
        f["local_clustering"]       = round(local_cc.get(f["va"], 0.0), 4)
        f["export_distance"]        = ex_dist.get(f["va"], -1)

    return results


def print_components(components: list[dict], top: int = 15) -> None:
    """Print WCC component summary sorted by size."""
    singletons = [c for c in components if c["size"] == 1]
    multi      = [c for c in components if c["size"] > 1]

    print(f"\nCOMPONENT ANALYSIS: {len(components)} total WCCs")
    print(f"  Multi-node: {len(multi)}   Singletons: {len(singletons)}")
    print()
    print(f"  {'ID':>3}  {'SIZE':>5}  {'DENSITY':>7}  {'MAX_K':>5}  "
          f"{'CC_AVG':>6}  {'REACH':>5}  {'ROLE':<24}  TOP_HUB")
    print(f"  {'-'*3}  {'-'*5}  {'-'*7}  {'-'*5}  {'-'*6}  {'-'*5}  "
          f"{'-'*24}  {'-'*30}")

    for c in multi[:top]:
        reach = "YES" if c["reachable_from_seeds"] else "NO"
        hub   = c.get("top_hub_name") or (c.get("top_hub_va") or "")[:20]
        print(f"  {c['id']:>3}  {c['size']:>5}  {c['density']:>7.4f}  "
              f"{c['max_k_core']:>5}  {c['avg_local_clustering']:>6.3f}  "
              f"{reach:>5}  {c['role']:<24}  {hub}")

    if singletons:
        print(f"\n  ... {len(singletons)} singleton components (isolated leaves)")


# ── Main annotator ────────────────────────────────────────────────────────────

def _seed_reachable(seed_vas: set[str], adj: dict[str, list[str]]) -> set[str]:
    """BFS from seeds following call edges. Returns all reachable VAs."""
    visited = set(seed_vas)
    queue   = deque(seed_vas)
    while queue:
        v = queue.popleft()
        for w in adj.get(v, []):
            if w not in visited:
                visited.add(w)
                queue.append(w)
    return visited


def compute_metrics(functions: list[dict],
                    seed_vas: set[str] | None = None) -> dict[str, dict]:
    """
    Compute call graph topology metrics for a list of function dicts.
    Each dict must have 'va', 'called_vas', 'size'.

    seed_vas: set of VA strings for seed/exported functions. When provided,
              betweenness and graph_rank are computed only within the subgraph
              reachable from seeds — avoiding the CRT init cluster contamination.
              Functions NOT reachable from seeds get noise_cluster=True.

    Returns {va: {k_core, betweenness, in_degree, out_degree, graph_rank, noise_cluster}}.

    Additional noise detection: functions whose entire named callee set consists only of
    libc/stdio/OS primitives and have no domain-specific callees are runtime formatting
    noise (e.g. MinGW __pformat, demangler) even when reachable from seeds via printf chains.
    These get noise_cluster=True regardless of reachability. Toolchain-agnostic: the callee
    pattern (fputc, localeconv, wcslen, strerror, _errno, putchar, fputs) is identical
    across MSVC/GCC/Clang runtime implementations.
    """
    vas    = [f["va"] for f in functions]
    va_set = set(vas)

    # Build directed adjacency (caller → callees)
    adj:     dict[str, list[str]] = {f["va"]: [] for f in functions}
    adj_rev: dict[str, list[str]] = {f["va"]: [] for f in functions}

    for f in functions:
        src = f["va"]
        for dst in f.get("called_vas", []):
            if dst in va_set:
                adj[src].append(dst)
                adj_rev[dst].append(src)

    # Determine noise cluster (not reachable from seeds)
    if seed_vas:
        reachable = _seed_reachable(seed_vas & va_set, adj)
        # Also include seeds themselves even if they have no in-edges
        reachable |= (seed_vas & va_set)
    else:
        reachable = va_set   # no seed info: use all nodes

    algo_vas  = [v for v in vas if v in reachable]
    noise_vas = {v for v in vas if v not in reachable}

    # K-core on full undirected graph (structural property regardless of seeds)
    adj_u: dict[str, set[str]] = {v: set() for v in vas}
    for src, dsts in adj.items():
        for dst in dsts:
            adj_u[src].add(dst)
            adj_u[dst].add(src)
    k_core = _k_core_numbers(adj_u)

    # Betweenness ONLY within seed-reachable subgraph
    # Source nodes = seed functions (they're the entry points that matter)
    algo_adj = {v: [w for w in adj.get(v, []) if w in reachable]
                for v in algo_vas}
    if seed_vas and algo_vas:
        # Run betweenness using only seeds as sources for directional accuracy
        sources = [v for v in algo_vas if v in seed_vas]
        if not sources:
            sources = algo_vas   # fallback: all reachable
        bet = _betweenness_centrality(algo_vas, algo_adj)
    else:
        bet = _betweenness_centrality(algo_vas, algo_adj)

    # Libc-only callee detection: functions whose ALL named callees are pure
    # libc/stdio/OS primitives are runtime formatting/support noise even when
    # reachable from seeds (they get pulled in via printf chains).
    # Toolchain-agnostic: these callee names are stable across MSVC/GCC/Clang.
    _LIBC_ONLY = frozenset({
        "fputc", "fputs", "fwrite", "putchar", "putc",
        "localeconv", "wcslen", "strlen", "strerror", "strnlen",
        "_errno", "__errno", "errno", "ferror",
        "MultiByteToWideChar", "WideCharToMultiByte",
        "___lc_codepage_func", "___mb_cur_max_func",
        "malloc", "free", "calloc", "realloc", "memcpy", "memset", "memmove",
        "_write", "_read", "_lseeki64",
        "wcstombs", "mbstowcs", "isprint", "isspace",
    })

    func_named_callees: dict[str, list[str]] = {}
    for f in functions:
        func_named_callees[f["va"]] = f.get("named_callees", [])

    # Build callee reference counts for data-driven utility detection
    # (replaces _LIBC_ONLY vocabulary — no keyword list needed)
    _callee_ref_count: Counter = Counter()
    for f in functions:
        for c in f.get("named_callees", []):
            _callee_ref_count[c] += 1
    _N = max(len(functions), 1)

    # Relative IDF threshold: a callee is "utility-like" if its IDF < 65% of max_idf.
    # This scales with binary size: for N=3242, threshold≈7.6 bits, catching functions
    # called by ≥N/2^7.6 ≈ 21+ callers (memset/malloc range).
    # For N=4522 (ntdll), threshold≈7.9 bits — similar relative range.
    # Uses relative threshold so the filter works across binaries of different sizes.
    _max_idf = math.log2(max(_N, 2))
    _utility_idf_threshold = _max_idf * 0.65

    def _is_libc_only_noise(va: str) -> bool:
        """
        True if this FUN_* calls only widely-referenced (utility-like) functions.
        Data-driven replacement for _LIBC_ONLY vocabulary set.

        A callee is utility-like if its IDF < 65% of binary max_idf.
        This threshold naturally catches memset/malloc/free/strlen across binary sizes
        without a hardcoded vocabulary list.
        """
        if not va.startswith("0x"):
            return False
        callees = func_named_callees.get(va, [])
        if not callees:
            return False
        named_external = [c for c in callees if not c.startswith("FUN_")]
        if not named_external:
            return False
        return all(
            math.log2(_N / max(_callee_ref_count.get(c, 1), 1)) < _utility_idf_threshold
            for c in named_external
        )

    result = {}
    for f in functions:
        va     = f["va"]
        size   = f.get("size", 1)
        in_deg  = len(adj_rev.get(va, []))
        out_deg = len(adj.get(va, []))
        b = bet.get(va, 0.0)
        k = k_core.get(va, 0)

        # Noise: structurally unreachable from seeds OR libc-only callee pattern
        is_noise = (va in noise_vas) or _is_libc_only_noise(va)

        # graph_rank: betweenness × complexity / specificity
        if va in (seed_vas or set()):
            rank = math.log(size + 1) * 0.01
        else:
            rank = b * math.log(size + 1) / (in_deg + 1) if not is_noise else 0.0

        result[va] = {
            "k_core":        k,
            "betweenness":   round(b, 5),
            "in_degree":     in_deg,
            "out_degree":    out_deg,
            "graph_rank":    round(rank, 6),
            "noise_cluster": is_noise,
            "is_seed":       va in (seed_vas or set()),
        }
    return result


def _annotate_caller_diversity(functions: list[dict]) -> None:
    """
    Add caller_diversity: Shannon entropy of WCC component IDs among callers.
    Requires component_id to already be set (run after analyze_components).

    High diversity  = called from many different structural regions = cross-cutting
    Low diversity   = called from one region only = domain-internal

    External callees (malloc, memset, etc.) are handled via reverse map from
    named_callees lists, so they get component diversity from their callers.

    Then update utility_score to the COMPOSITE of all three axes:
      caller_count_signal  — how widely referenced
      callee_idf_signal    — how generic the things it calls are (1 - mean_callee_idf/max)
      caller_diversity     — how structurally diverse its callers are

    Utility requires ALL THREE to be high (geometric mean → 0 if any is 0).
    RegisterObject: high caller_count, moderate callee_idf (calls domain things),
                    LOW diversity (all game-object callers in same component) → NOT utility.
    memset:         high caller_count, low callee_idf (calls OS primitives),
                    HIGH diversity (called from every subsystem) → utility.
    """
    from collections import defaultdict

    # Build reverse maps: callee_name → [caller component_ids] and [caller classes]
    callee_to_comps: dict[str, list[int]] = defaultdict(list)
    callee_to_class: dict[str, list[str]] = defaultdict(list)
    fn_by_name: dict[str, dict] = {fn["name"]: fn for fn in functions}

    for fn in functions:
        comp  = fn.get("component_id", -1)
        cls   = fn.get("dominant_class", "UNKNOWN")
        for callee in fn.get("named_callees", []):
            callee_to_comps[callee].append(comp)
            callee_to_class[callee].append(cls)

    max_idf      = math.log2(max(len(functions), 2))
    n_components = max((fn.get("component_id", 0) for fn in functions), default=1) + 1
    max_div      = math.log2(max(n_components, 2))

    for fn in functions:
        # Caller component distribution for THIS function
        comp_ids = callee_to_comps.get(fn["name"], [])
        # Fallback: use calling_names if reverse map missed some
        if not comp_ids:
            for cname in fn.get("calling_names", []):
                caller = fn_by_name.get(cname)
                if caller:
                    comp_ids.append(caller.get("component_id", -1))

        valid = [c for c in comp_ids if c >= 0]
        comp_ent = 0.0
        if valid:
            counts = Counter(valid)
            total  = sum(counts.values())
            comp_ent = -sum((c/total)*math.log2(c/total) for c in counts.values() if c > 0)
        fn["caller_diversity"] = round(max(comp_ent, 0.0), 3)

        # Caller content diversity: entropy of callers' dominant_class distribution.
        # Fixes "utility within domain" false positive (e.g. ARM7 memory bus called
        # by 258 handlers that are ALL MEMORY-dominant → class entropy ≈ 0 → NOT utility).
        # Cross-cutting utilities (RtlCopyMemory, memset) have callers doing diverse
        # things: GUARD, ORCHESTRATE, COMPUTE, MEMORY → high class entropy.
        # Works regardless of WCC topology — content-based, not structure-based.
        caller_classes = callee_to_class.get(fn["name"], [])
        if not caller_classes:
            for cname in fn.get("calling_names", []):
                caller = fn_by_name.get(cname)
                if caller:
                    caller_classes.append(caller.get("dominant_class", "UNKNOWN"))
        class_ent = 0.0
        if caller_classes:
            cc = Counter(caller_classes)
            tot = sum(cc.values())
            class_ent = -sum((v/tot)*math.log2(v/tot) for v in cc.values() if v > 0)
        fn["caller_class_diversity"] = round(class_ent, 3)

        n_callers  = fn.get("caller_count", 0)
        mean_idf   = fn.get("mean_callee_idf", 0.0)
        # Combined diversity: max of component diversity and content diversity.
        # Component diversity works for multi-component graphs.
        # Content diversity works for monolithic graphs (mGBA).
        # Taking max means EITHER signal can rescue cross-cutting utilities.
        max_class_ent = math.log2(max(len({f.get("dominant_class","?")
                                           for f in functions}), 2))
        class_div_norm = class_ent / max_class_ent if max_class_ent > 0 else 0.0
        comp_div_norm  = comp_ent  / max_div       if max_div       > 0 else 0.0
        combined_div   = max(class_div_norm, comp_div_norm)

        if n_callers == 0:
            fn["utility_score"] = 0.0
            continue

        caller_sig  = min(n_callers / max(len(functions) * 0.05, 1), 1.0)
        has_callees = bool(fn.get("named_callees"))
        callee_sig  = (1.0 - mean_idf / max_idf) if (has_callees and max_idf > 0) else 0.5
        diverse_sig = combined_div

        # Weights: caller=0.30, callee=0.40, diversity=0.30
        # Diversity now carries more weight since content diversity is more reliable.
        utility = 0.30 * caller_sig + 0.40 * callee_sig + 0.30 * diverse_sig

        # Hard gate: high callee_idf → calls domain-specific things → not utility
        if mean_idf > max_idf * 0.60:
            utility = min(utility, 0.30)

        fn["utility_score"] = round(utility, 3)


def _annotate_callee_idf(functions: list[dict]) -> None:
    """
    Compute callee IDF and annotate each function with:
      mean_callee_idf  — mean IDF of named callees. Replaces _LIBC_ONLY vocab filter.
      max_callee_idf   — highest-IDF callee (the most domain-specific thing this fn calls)
      utility_score    — inverse: 1 - mean_callee_idf/log2(N). High=utility, Low=domain.

    callee_idf(C) = -log2(reference_count(C) / N)
      High → C is called by few functions → domain-specific → discriminating about its callers
      Low  → C is called by many functions → utility → not discriminating

    Per-function interpretation:
      mean_callee_idf LOW  (< 2.0) → calls mostly utilities → likely IS a utility / generic layer
      mean_callee_idf HIGH (> 5.0) → calls domain-specific functions → subsystem member

    Replaces the hardcoded _LIBC_ONLY vocabulary filter. No keyword lists needed:
    memset/malloc/strlen naturally get low IDF because many diverse functions reference them.
    Domain-specific handlers (DMA, SWI, audio) get high IDF because few functions call them.
    Works for any language, any toolchain, any domain — purely data-driven.
    """
    N = max(len(functions), 1)
    max_idf = math.log2(N)  # IDF of a callee referenced by exactly 1 function

    # Count how many functions reference each named callee
    ref_count: dict[str, int] = Counter()
    for fn in functions:
        for c in fn.get("named_callees", []):
            ref_count[c] += 1

    for fn in functions:
        callees = fn.get("named_callees", [])
        if not callees:
            fn["mean_callee_idf"] = 0.0
            fn["max_callee_idf"]  = 0.0
            fn["utility_score"]   = 0.5   # no callees → neutral
            continue

        idfs = [math.log2(N / max(ref_count.get(c, 1), 1)) for c in callees]
        mean_idf = sum(idfs) / len(idfs)
        fn["mean_callee_idf"] = round(mean_idf, 3)
        fn["max_callee_idf"]  = round(max(idfs),  3)
        # utility_score: 0=pure domain-specific, 1=pure utility
        fn["utility_score"]   = round(1.0 - mean_idf / max_idf, 3) if max_idf > 0 else 0.5


def annotate_calltree(functions: list[dict],
                      seed_vas: set[str] | None = None) -> None:
    """
    Mutate function dicts in place, adding graph topology metrics.

    seed_vas: VA strings of seed/exported functions for seed-relative betweenness.
              If None, extracted from functions with depth=0 or is_seed flag.
    """
    if seed_vas is None:
        # Auto-detect seeds. Priority:
        # 1. Named (non-FUN_*) exports: survive stripping, are the natural entry points
        # 2. depth=0 functions from calltree BFS
        # 3. Functions with no callers but with callees (root nodes)
        _CRT_PREFIXES = ("__", "_pei386", "tls_callback", "entry", "DllMain",
                         "_register", "_execute", "_GetPE", "_IsNon", "_Find")
        named_exports = {
            f["va"] for f in functions
            if not f["name"].startswith("FUN_")
            and not any(f["name"].startswith(p) for p in _CRT_PREFIXES)
            and f["name"] not in ("", ".text")
        }
        if named_exports:
            seed_vas = named_exports
        else:
            depth0 = {f["va"] for f in functions if f.get("depth") == 0}
            seed_vas = depth0 if depth0 else {
                f["va"] for f in functions
                if not f.get("calling_names") and f.get("called_vas")
            }

    metrics = compute_metrics(functions, seed_vas=seed_vas)
    # Callee IDF — data-driven utility detection, no vocabulary list
    _annotate_callee_idf(functions)
    # NetworkX-powered metrics (SCC, PageRank, degree entropy, power-law)
    nx_summary = compute_networkx_metrics(functions, seed_vas=seed_vas)
    annotate_calltree._last_nx_summary = nx_summary
    # Component analysis (WCC, local clustering, export distance)
    _components = analyze_components(functions, seed_vas=seed_vas)
    annotate_calltree._last_components = _components
    # Caller diversity — needs component_id from analyze_components; also updates utility_score
    _annotate_caller_diversity(functions)
    for f in functions:
        m = metrics.get(f["va"], {})
        f["k_core"]        = m.get("k_core", 0)
        f["betweenness"]   = m.get("betweenness", 0.0)
        f["graph_rank"]    = m.get("graph_rank", 0.0)
        f["noise_cluster"] = m.get("noise_cluster", False)
        f["is_seed"]       = m.get("is_seed", False)
        if "graph_in_degree"  not in f: f["graph_in_degree"]  = m.get("in_degree", 0)
        if "graph_out_degree" not in f: f["graph_out_degree"] = m.get("out_degree", 0)


def print_ranked(functions: list[dict], top_n: int = 0) -> None:
    """Print functions sorted by graph_rank descending, noise cluster separated."""
    from collections import Counter

    algo  = [f for f in functions if not f.get("noise_cluster")]
    noise = [f for f in functions if f.get("noise_cluster")]

    ranked = sorted(algo, key=lambda f: f.get("graph_rank", 0), reverse=True)
    if top_n:
        ranked = ranked[:top_n]

    max_k = max((f.get("k_core", 0) for f in functions), default=1)

    print(f"{'RANK':>8}  {'K':>3}  {'BET':>7}  {'IN':>4}  {'OUT':>4}  {'SIZE':>6}  {'TAG':<5}  NAME")
    print("-" * 90)
    for f in ranked:
        name = f.get("name", f["va"])
        tag  = "SEED" if f.get("is_seed") else "ALG"
        print(f"{f.get('graph_rank',0):8.5f}  "
              f"{f.get('k_core',0):3d}  "
              f"{f.get('betweenness',0):7.4f}  "
              f"{f.get('graph_in_degree', f.get('caller_count', 0)):4d}  "
              f"{f.get('graph_out_degree', f.get('callee_count', 0)):4d}  "
              f"{f.get('size',0):6d}  "
              f"{tag:<5}  {name}")

    if noise:
        print(f"\n[NOISE CLUSTER — {len(noise)} functions excluded from LLM prompt]")
        for f in sorted(noise, key=lambda x: -x.get("size", 0))[:5]:
            print(f"  {f.get('size',0):6d}  {f.get('name', f['va'])}")
        if len(noise) > 5:
            print(f"  ... and {len(noise)-5} more")

    dist = Counter(f.get("k_core", 0) for f in functions)
    print(f"\nK-core distribution (all): {dict(sorted(dist.items()))}")
    print(f"Noise cluster: {len(noise)}/{len(functions)} functions "
          f"({100*len(noise)//max(len(functions),1)}%)")


# ── NetworkX-powered metrics ─────────────────────────────────────────────────
#
# SCC, PageRank, degree entropy, power-law exponent.
# All O(V+E) or O(V*log V) — negligible cost on 1K-10K node call graphs.
# These are the "mathematical elders" metrics: borrowed from network science,
# validated on biological/social/software networks, free via networkx.
#
# Design: build the DiGraph ONCE from calltree functions, run all algorithms,
# annotate per-function dicts in place and return a binary-level summary dict.

def compute_networkx_metrics(
    functions: list[dict],
    seed_vas:  set[str] | None = None,
) -> dict:
    """
    Compute SCC decomposition, PageRank, degree entropy, and power-law exponent
    for a calltree. Annotates each function dict in place with new fields and
    returns a binary-level summary dict.

    New per-function fields:
      pagerank      float   Directional prestige. High = called by important fns.
                            Complements betweenness (which measures path flow).
      scc_size      int     Size of the SCC this function belongs to.
                            1  = function is not part of any call cycle (acyclic).
                            >1 = mutual recursion / callback loop.
      scc_rank      int     Topological rank in the condensation DAG (0=source).
                            Low rank = near entry points. High rank = deep impl.
      in_degree_nx  int     In-degree in the full call graph (networkx, exact).
      out_degree_nx int     Out-degree in the full call graph.

    Binary-level summary:
      n_sccs              int    Number of strongly connected components.
      largest_scc_size    int    Size of the largest SCC (>1 = recursion present).
      scc1_fraction       float  Fraction of functions with scc_size=1 (acyclic).
      degree_entropy_in   float  Shannon entropy of indegree distribution.
                                 High = many functions have similar in-degree (dispatch/flat).
                                 Low  = scale-free (hub-and-spoke, typical library).
      degree_entropy_out  float  Shannon entropy of outdegree distribution.
      powerlaw_alpha_in   float  Power-law exponent α for indegree (None if poor fit).
                                 Typical compiled binary: α ≈ 2–3.
                                 Deviation: template bloat (α<2), obfuscation (α>4).
      powerlaw_alpha_out  float  Same for outdegree.
      pagerank_top5       list   Top-5 function names by PageRank.
    """
    try:
        import networkx as nx
    except ImportError:
        # Graceful degradation: annotate with None, return empty summary
        for f in functions:
            f.setdefault("pagerank", None)
            f.setdefault("scc_size", None)
            f.setdefault("scc_rank", None)
        return {"error": "networkx not available"}

    # ── Build DiGraph ─────────────────────────────────────────────────────────
    va_set = {f["va"] for f in functions}
    fn_by_va = {f["va"]: f for f in functions}

    G = nx.DiGraph()
    G.add_nodes_from(va_set)
    for f in functions:
        for dst in f.get("called_vas", []):
            if dst in va_set:
                G.add_edge(f["va"], dst)

    # ── SCC decomposition ─────────────────────────────────────────────────────
    sccs = list(nx.strongly_connected_components(G))
    va_to_scc_size: dict[str, int] = {}
    for scc in sccs:
        sz = len(scc)
        for va in scc:
            va_to_scc_size[va] = sz

    # DAG condensation for topological rank (depth from sources in condensed graph)
    try:
        cond = nx.condensation(G)   # DiGraph of SCCs
        # Map SCC index back to member VAs (networkx stores 'members' attr)
        scc_to_rank: dict[int, int] = {}
        for n in nx.topological_sort(cond):
            preds = list(cond.predecessors(n))
            rank = 0 if not preds else max(scc_to_rank.get(p, 0) for p in preds) + 1
            scc_to_rank[n] = rank
        # cond nodes have 'members' attr = set of original node VAs
        va_to_scc_rank: dict[str, int] = {}
        for n, data in cond.nodes(data=True):
            r = scc_to_rank.get(n, 0)
            for va in data.get("members", set()):
                va_to_scc_rank[va] = r
    except Exception:
        va_to_scc_rank = {va: 0 for va in va_set}

    # ── PageRank ──────────────────────────────────────────────────────────────
    try:
        pr = nx.pagerank(G, alpha=0.85, max_iter=200, tol=1e-6)
    except Exception:
        pr = {va: 0.0 for va in va_set}

    # ── Per-function: size class + pseudocode instruction ratios ─────────────
    # Size and instruction mix are INDEPENDENT of call graph structure — the only
    # signals that characterise isolated singletons where all graph metrics are zero.
    #
    # Instruction ratios from pseudocode (cheap approximation, no disassembler):
    #   arith_ratio  = arithmetic ops / total ops  → high = pure computation
    #   call_ratio   = call expressions / total ops → high = orchestrator
    #   branch_ratio = branching keywords / total ops → high = guard/dispatcher
    #   deref_ratio  = pointer dereferences / total ops → high = memory-intensive
    #
    # DEFER: byte-level disassembly (capstone) for exact ISA-level instruction mix.
    # Calibrate thresholds (>0.4 arith → algorithm?) with labeled benchmark data.
    # The feature is validated in SAFE/Bingo/instruction2vec literature; only
    # threshold values need experiment.

    import re as _re

    # GUARD: split arith into two tiers to avoid overcounting pointer arithmetic.
    # Structural pointer ops (param_1 + 0x18, ptr + 1) inflate arith_ratio and
    # make every function look COMPUTE-heavy — a vacuousness risk confirmed by
    # 82-85% COMPUTE across all binaries in our first run.
    #
    # pure_arith: algorithmic signal — bitwise mixing, magic constants, shifts
    #   These survive optimization and identify crypto/hash/codec character.
    # ptr_arith:  structural noise — address computations, struct field offsets
    #   These are present in virtually ALL functions; not discriminating.
    #
    # arith_ratio = pure_arith only. Calibrate thresholds with benchmark data.

    # ── Format string semantic classification ────────────────────────────────
    # String literals in pseudocode carry exact programmer intent — completely
    # deterministic, zero calibration, zero false positives for the categories below.
    # A function containing "not implemented" is ALWAYS a known gap.
    # A function containing "write to read-only" is ALWAYS a trap handler.
    # These surface richness signals AND structural facts simultaneously.
    #
    # Implementation: keyword scan on pseudocode string content.
    # Strings appear as: "literal text" in call args or TOOLKIT_NOTE resolutions.

    # Strings ≥4 chars, containing at least one space (real messages have spaces;
    # Ghidra code fragments usually don't). Excludes pure identifiers and paths.
    _STR_LITERAL = _re.compile(r'"([^"]{4,})"')
    _STR_HAS_SPACE = _re.compile(r'[a-zA-Z] [a-zA-Z]')  # at least one word boundary

    # Keyword → semantic class. Order matters: first match wins.
    _FMT_KEYWORDS: list[tuple[str, str]] = [
        ("not implemented",     "KNOWN_GAP"),
        ("unimplemented",       "KNOWN_GAP"),
        (" todo ",              "KNOWN_GAP"),    # word-boundary: avoid "toDosError" match
        ("fixme",              "KNOWN_GAP"),
        ("stub",                "PARTIAL_IMPL"),
        ("read-only",           "TRAP_HANDLER"),
        ("read only",           "TRAP_HANDLER"),
        ("write to read",       "TRAP_HANDLER"),
        ("write to unused",     "TRAP_HANDLER"),
        ("write to bios",       "TRAP_HANDLER"),
        ("reserved",            "TRAP_HANDLER"),
        ("deprecated",          "LEGACY_CODE"),
        ("assert",              "ASSERTION"),
        ("invalid",             "VALIDATION_FAIL"),
        ("illegal",             "VALIDATION_FAIL"),
        ("out of range",        "VALIDATION_FAIL"),
        ("overflow",            "VALIDATION_FAIL"),
    ]

    def _classify_format_strings(pcode: str) -> tuple[str, list[str]]:
        """
        Return (semantic_class, matched_strings) from string literals in pseudocode.
        semantic_class is NONE if no semantic keywords found.
        Priority: KNOWN_GAP > TRAP_HANDLER > PARTIAL_IMPL > VALIDATION_FAIL > LEGACY_CODE.
        """
        if not pcode:
            return "NONE", []
        strings = [m.group(1).lower() for m in _STR_LITERAL.finditer(pcode)
                   if _STR_HAS_SPACE.search(m.group(1))]  # only human-readable strings
        hits: list[str] = []
        best = "NONE"
        priority = {"KNOWN_GAP": 5, "TRAP_HANDLER": 4, "PARTIAL_IMPL": 3,
                    "VALIDATION_FAIL": 2, "ASSERTION": 1, "LEGACY_CODE": 1, "NONE": 0}
        for s in strings:
            for kw, cls in _FMT_KEYWORDS:
                if kw in s:
                    hits.append(f"{cls}:{s[:50]}")
                    if priority.get(cls, 0) > priority.get(best, 0):
                        best = cls
                    break
        return best, hits

    # ── Constant structure analysis ───────────────────────────────────────────
    # Constants in pseudocode are semantic intent left by the programmer.
    # Their VALUE DISTRIBUTION is free, cheap, and highly discriminating:
    #
    #   struct_cluster_score: CoV of small constants (<0x4000).
    #     Low CoV (constants tightly clustered) → struct field access.
    #     High CoV or few small constants → not primarily struct access.
    #
    #   ntstatus_frac: fraction of constants matching 0xC[0-9a-f]{7}.
    #     Any > 0 in a function is a strong GUARD / error-handler signal.
    #
    #   range_hist: how constants distribute across magnitude bands.
    #     Bands: small(<0x2000), medium(0x2000-0xFFFF), large(0x10000-0x3FFFFFFF),
    #            hw_addr(0x4000000+), algo_magic(0x10000000+ and >4 unique bits set)
    #
    #   const_entropy: Shannon entropy of the constant value distribution.
    #     High → diverse algorithmic constants (crypto/hash).
    #     Low  → repeated loop counters / sentinel values.
    #
    # DEFER: primality test (signal strength unknown without experiments).
    # DEFER: exact threshold calibration for struct_cluster_score.

    _HEX_CONST  = _re.compile(r'0x([0-9a-fA-F]+)')
    _DEC_CONST  = _re.compile(r'(?<![0-9a-fA-F])\b([1-9][0-9]{3,})\b')  # decimals ≥1000
    _NTSTATUS   = _re.compile(r'0x[Cc][0-9a-fA-F]{7}\b')

    def _analyze_constants(pcode: str) -> dict:
        if not pcode or len(pcode) < 20:
            return {"struct_cluster": 0.0, "ntstatus_frac": 0.0,
                    "const_entropy": 0.0, "range_small": 0,
                    "range_medium": 0, "range_large": 0, "range_hwaddr": 0,
                    "n_unique_consts": 0}

        # Collect all constants
        vals = []
        for m in _HEX_CONST.finditer(pcode):
            try:
                vals.append(int(m.group(1), 16))
            except ValueError:
                pass
        for m in _DEC_CONST.finditer(pcode):
            try:
                vals.append(int(m.group(1)))
            except ValueError:
                pass

        # Filter noise: 0, 1, 2, 3, 4, 0xFF, 0xFFFF (universal, not discriminating)
        _NOISE = {0, 1, 2, 3, 4, 8, 0xF, 0xFF, 0xFFFF, 0xFFFFFFFF}
        vals = [v for v in vals if v not in _NOISE and v > 0]

        if not vals:
            return {"struct_cluster": 0.0, "ntstatus_frac": 0.0,
                    "const_entropy": 0.0, "range_small": 0,
                    "range_medium": 0, "range_large": 0, "range_hwaddr": 0,
                    "n_unique_consts": 0}

        n_total = len(vals)
        unique  = list(set(vals))

        # Range histogram
        r_small  = sum(1 for v in vals if v < 0x2000)
        r_medium = sum(1 for v in vals if 0x2000 <= v < 0x10000)
        r_large  = sum(1 for v in vals if 0x10000 <= v < 0x4000000)
        r_hw     = sum(1 for v in vals if v >= 0x4000000)

        # Alignment stride analysis — distinguishes MMIO from error codes.
        # Key insight: hardware registers are aligned (stride = power of 2, ≤ 16).
        # Error codes (NTSTATUS 0xCxxxxxxx, SEH codes) have irregular strides.
        # Port addresses: stride ≤ 4 (byte/word/dword aligned port spacing).
        # MMIO regions: stride is power of 2, often 2 or 4 for register spacing.
        hw_vals = sorted(set(v for v in vals if v >= 0x4000000))
        stride_is_aligned = False
        hw_enough_to_judge = len(hw_vals) >= 3
        if hw_enough_to_judge:
            strides = [hw_vals[i+1] - hw_vals[i] for i in range(len(hw_vals)-1)]
            def _is_pow2(n): return n > 0 and (n & (n-1)) == 0
            aligned_count = sum(1 for s in strides if _is_pow2(s) and s <= 16)
            stride_is_aligned = aligned_count >= len(strides) * 0.6

        # Struct clustering: CoV of small constants.
        # Low CoV = constants are tightly grouped = struct field access.
        small_vals = [v for v in vals if v < 0x4000]
        struct_cluster = 0.0
        if len(small_vals) >= 3:
            mean = sum(small_vals) / len(small_vals)
            if mean > 0:
                std  = (sum((v - mean)**2 for v in small_vals) / len(small_vals)) ** 0.5
                # INVERT CoV so high score = more clustered (= more struct-like)
                cov  = std / mean
                struct_cluster = round(1.0 / (1.0 + cov), 3)

        # NTSTATUS fraction
        n_ntstatus   = len(_NTSTATUS.findall(pcode))
        ntstatus_frac = round(n_ntstatus / max(n_total, 1), 3)

        # Constant entropy (over unique values)
        counts = Counter(vals)
        total  = sum(counts.values())
        entropy = -sum((c/total) * math.log2(c/total)
                       for c in counts.values() if c > 0)

        return {
            "struct_cluster":   struct_cluster,  # 0-1, high = struct fields
            "ntstatus_frac":    ntstatus_frac,   # >0 = error-handling code
            "const_entropy":    round(entropy, 3),
            "range_small":      r_small,         # constants < 0x2000
            "range_medium":     r_medium,        # 0x2000 – 0xFFFF
            "range_large":      r_large,         # 0x10000 – 0x3FFFFFF
            "range_hwaddr":         r_hw,             # ≥ 0x4000000 (MMIO / kernel / algo)
            "hw_stride_aligned":    stride_is_aligned,    # True = MMIO (power-of-2 strides)
            "hw_enough_to_judge":   hw_enough_to_judge,  # True = had ≥3 hw_addr consts to analyse
            "n_unique_consts":      len(unique),
        }

    _PURE_ARITH = _re.compile(
        r'0x[0-9a-fA-F]{4,}'      # magic constants (≥4 hex digits = likely algo)
        r'|>>|<<'                  # bit shifts
        r'|\^'                     # XOR (rare outside bit manipulation)
        r'|\*\s*0x[0-9a-fA-F]+'   # multiply by constant
        r'|\*\s*[0-9]{4,}'        # multiply by large decimal constant
    )
    # Split _BRANCH into components — blending them was too noisy.
    # Theoretically justified without benchmark data:
    #   loop_count / size  → 0 = guard/orchestrate;  1+ = compute/dispatch
    #   if_count   / size  → high = guard or fine-grained dispatch; low = compute
    #   return_count/size  → high = many early exits = guard; low = single exit = compute
    # Depth of nesting deliberately NOT measured — humans cap at 3-4 levels,
    # range is too narrow to discriminate. Density is the signal, not depth.
    _LOOPS   = _re.compile(r'\b(?:while|for)\b')
    _IFS     = _re.compile(r'\bif\b')
    _RETURNS = _re.compile(r'\breturn\b')
    _DEREF   = _re.compile(r'\*\s*\(|\*[a-zA-Z_]|\->')
    _CALL    = _re.compile(r'\b[A-Za-z_]\w+\s*\(')
    # Function pointer installs: assignment of a function address to a pointer slot.
    # Covers: = FUN_xxx (stripped/Ghidra unnamed) AND = NamedFunc (named functions).
    # NOT followed by '(' — that would be a call, not an install.
    # Orthogonal to call_ratio: measures what a function INSTALLS, not what it CALLS.
    _FPTR_INSTALL = _re.compile(
        r'=\s*FUN_[0-9a-fA-F]+(?!\s*\()'          # stripped: = FUN_20cxxxxx
        r'|=\s*[A-Z][A-Za-z0-9_]{3,}(?!\s*\()'    # named: = RtlAllocateHeap (≥4 chars, caps start)
    )

    def _instr_ratios(pcode: str, size: int) -> dict:  # noqa: E301
        """
        Returns per-function structural ratios.
        All divided by max(size,1) so they're comparable across function sizes.
        """
        if not pcode or len(pcode) < 10:
            return {"arith_ratio":0.0,"call_ratio":0.0,"deref_ratio":0.0,
                    "if_density":0.0,"loop_count":0,"return_density":0.0,
                    "has_loops":False}
        sz = max(size, 1)
        n_arith        = len(_PURE_ARITH.findall(pcode))
        n_call         = len(_CALL.findall(pcode))
        n_deref        = len(_DEREF.findall(pcode))
        n_loops        = len(_LOOPS.findall(pcode))
        n_if           = len(_IFS.findall(pcode))
        n_return       = len(_RETURNS.findall(pcode))
        n_fptr_install = len(_FPTR_INSTALL.findall(pcode))
        op_total  = max(n_arith + n_call + n_deref + n_loops + n_if + n_return, 1)
        return {
            "arith_ratio":       round(n_arith         / op_total, 3),
            "call_ratio":        round(n_call           / op_total, 3),
            "deref_ratio":       round(n_deref          / op_total, 3),
            "if_density":        round(n_if             / sz,       4),
            "loop_count":        n_loops,
            "return_density":    round(n_return         / sz,       4),
            "has_loops":         n_loops > 0,
            "fptr_install_count": n_fptr_install,        # raw count
            "fptr_install_density": round(n_fptr_install / sz, 4),  # per instruction
        }

    def _size_class(n: int) -> str:
        if n <  10:  return "TINY"
        if n <  50:  return "SMALL"
        if n < 200:  return "MEDIUM"
        if n < 1000: return "LARGE"
        return "MONOLITH"

    for f in functions:
        sz  = f.get("size", 0)
        pcode = f.get("pseudocode") or ""
        f["size_class"] = _size_class(sz)
        r  = _instr_ratios(pcode, sz)
        cr = _analyze_constants(pcode)

        f["arith_ratio"]     = r["arith_ratio"]
        f["call_ratio"]      = r["call_ratio"]
        f["deref_ratio"]     = r["deref_ratio"]
        f["if_density"]            = r["if_density"]
        f["loop_count"]            = r["loop_count"]
        f["return_density"]        = r["return_density"]
        f["has_loops"]             = r["has_loops"]
        f["fptr_install_count"]    = r["fptr_install_count"]
        f["fptr_install_density"]  = r["fptr_install_density"]
        fmt_class, fmt_hits        = _classify_format_strings(pcode)
        f["fmt_str_class"]         = fmt_class   # KNOWN_GAP | TRAP_HANDLER | etc.
        f["fmt_str_hits"]          = fmt_hits[:3] # first 3 matching strings
        # Constant profile
        f["struct_cluster"]  = cr["struct_cluster"]
        f["ntstatus_frac"]   = cr["ntstatus_frac"]
        f["const_entropy"]   = cr["const_entropy"]
        f["range_hwaddr"]       = cr["range_hwaddr"]
        f["hw_stride_aligned"]  = cr.get("hw_stride_aligned", False)
        f["n_unique_consts"] = cr["n_unique_consts"]

        # Dominant class — now uses constant structure as a primary signal.
        # Constant structure is theoretically justified without experiments.
        # Branch/loop signals are secondary discriminants.
        if not pcode:
            f["dominant_class"] = "UNKNOWN"
        elif fmt_class == "KNOWN_GAP":
            f["dominant_class"] = "KNOWN_GAP"       # exact: string "not implemented"
        elif fmt_class == "TRAP_HANDLER":
            f["dominant_class"] = "TRAP_HANDLER"    # exact: string "read-only"/"reserved"
        elif r["fptr_install_density"] > 0.02 and r["call_ratio"] < 0.30:
            # Installs function pointers but makes few direct calls
            # → CPS callback installer, state machine transition, vtable builder
            f["dominant_class"] = "CPS_CALLBACK"
        elif cr["ntstatus_frac"] > 0.05:
            # NTSTATUS constants → error-handler / guard — high precision
            f["dominant_class"] = "GUARD"
        elif cr["range_hwaddr"] >= 3 and cr["struct_cluster"] < 0.5:
            # Multiple large/HW-range constants, not struct-clustered → likely MMIO or algo.
            # Stride alignment discriminates error codes from genuine hardware registers:
            #   - MMIO / hardware: registers have power-of-2 aligned strides (2, 4, 8)
            #   - Error codes (NTSTATUS, SEH): irregularly enumerated, non-power-of-2 strides
            # Only DOWNGRADE to non-MMIO when we have enough hw_addr constants to judge
            # stride AND the strides are confirmed irregular. Default = MMIO_DISPATCH.
            # Asymmetric cost: MMIO→error is much worse than error→MMIO.
            # Only downgrade when we have HIGH CONFIDENCE this is an error code function:
            # - Has confirmed NTSTATUS constants (ntstatus_frac > 0): clear error handler
            # - AND the hw_addr strides are irregular (not power-of-2 aligned)
            # This specifically targets vcruntime140-style SEH handlers which have both
            # NTSTATUS codes AND irregular hw_addr constants, while preserving genuine
            # MMIO dispatch functions that happen to have mixed stride sizes (GBA, VGA, etc.)
            is_confirmed_error_codes = (
                cr.get("ntstatus_frac", 0) > 0 and           # has ≥1 NTSTATUS-range constant
                cr.get("hw_enough_to_judge", False) and        # enough hw_addr consts to judge
                not cr.get("hw_stride_aligned", False)         # AND strides are irregular
            )
            if is_confirmed_error_codes:
                f["dominant_class"] = "GUARD"      # NTSTATUS error handler, not MMIO
            elif r["arith_ratio"] > 0.25:
                f["dominant_class"] = "COMPUTE"    # restore original COMPUTE split
            else:
                f["dominant_class"] = "MMIO_DISPATCH"
        elif cr["struct_cluster"] > 0.6 and cr["range_small"] >= 3:
            # Tightly clustered small constants → struct field access
            f["dominant_class"] = "MEMORY"
        elif not r["has_loops"] and r["return_density"] > 0.05:
            f["dominant_class"] = "GUARD"
        elif r["arith_ratio"] > 0.45:
            f["dominant_class"] = "COMPUTE"
        elif r["call_ratio"] > 0.40:
            f["dominant_class"] = "ORCHESTRATE"
        elif r["has_loops"] and r["if_density"] > 0.06:
            f["dominant_class"] = "FLAG_DISPATCH"
        elif r["deref_ratio"] > 0.35:
            f["dominant_class"] = "MEMORY"
        else:
            f["dominant_class"] = "MIXED"

    # ── Size distribution ─────────────────────────────────────────────────────
    sizes = [f.get("size", 0) for f in functions]

    def _gini(vals: list[int]) -> float:
        """Gini coefficient of a distribution. 0=equal, 1=single dominant value."""
        if not vals or sum(vals) == 0:
            return 0.0
        s = sorted(vals)
        n = len(s)
        cumsum = 0
        for i, v in enumerate(s, 1):
            cumsum += v * (2 * i - n - 1)
        return cumsum / (n * sum(s))

    size_gini    = round(_gini(sizes), 3)
    monolith_cnt = sum(1 for s in sizes if s >= 1000)
    tiny_cnt     = sum(1 for s in sizes if s < 10)

    # Dominant class distribution across all functions (binary fingerprint)
    dom_classes  = Counter(f.get("dominant_class", "UNKNOWN") for f in functions)

    # ── Degree distributions ──────────────────────────────────────────────────
    in_degrees  = [G.in_degree(v)  for v in va_set]
    out_degrees = [G.out_degree(v) for v in va_set]

    def _percentile(vals: list[int], p: float) -> int:
        if not vals:
            return 0
        s = sorted(vals)
        idx = max(0, min(int(len(s) * p / 100), len(s) - 1))
        return s[idx]

    def _degree_entropy(degrees: list[int]) -> float:
        if not degrees:
            return 0.0
        counts = Counter(degrees)
        total  = len(degrees)
        return -sum((c / total) * math.log2(c / total)
                    for c in counts.values() if c > 0)

    H_in  = _degree_entropy(in_degrees)
    H_out = _degree_entropy(out_degrees)

    # ── Reciprocal edge fraction ──────────────────────────────────────────────
    # Fraction of directed edges (u→v) where the reverse (v→u) also exists.
    # Low (< 5%) = typical human code (mostly one-way call relationships).
    # High (> 15%) = mutual recursion / circular deps / obfuscation.
    edges_set    = set(G.edges())
    n_reciprocal = sum(1 for u, v in edges_set if (v, u) in edges_set)
    recip_frac   = n_reciprocal / max(len(edges_set), 1)

    # ── PageRank + HITS ───────────────────────────────────────────────────────
    try:
        pr = nx.pagerank(G, alpha=0.85, max_iter=200, tol=1e-6)
    except Exception:
        pr = {va: 0.0 for va in va_set}

    # HITS authority/hub scores — theoretical grounding for callee_idf.
    # authority(v) = Σ hub(u) for callers u of v (iterative convergence).
    # High authority = widely pointed-to by important hubs = utility callee.
    # Stored for comparison with our callee_idf approach.
    try:
        _hits_hubs, _hits_auth = nx.hits(G, max_iter=100, tol=1e-6, normalized=True)
    except Exception:
        _hits_hubs = {va: 0.0 for va in va_set}
        _hits_auth = {va: 0.0 for va in va_set}

    # Betweenness for divergence computation (reuse if already computed elsewhere)
    # We only need it for the PR-BET divergence signal; use approximate if large
    try:
        if len(va_set) <= 2000:
            bet_nx = nx.betweenness_centrality(G, normalized=True)
        else:
            # k-sample approximation for large graphs
            bet_nx = nx.betweenness_centrality(G, normalized=True, k=min(500, len(va_set)))
    except Exception:
        bet_nx = {va: 0.0 for va in va_set}

    # ── Power-law exponent fitting + goodness-of-fit guard ───────────────────
    # GUARD: always compare power-law against exponential alternative.
    # A fit without a goodness-of-fit test is a number without evidence.
    # pl_better_than_exp = True means power-law is the better model (valid α).
    alpha_in = alpha_out = None
    pl_better_in = pl_better_out = None
    try:
        import powerlaw, warnings
        nonzero_in  = [d for d in in_degrees  if d > 0]
        nonzero_out = [d for d in out_degrees if d > 0]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            if len(nonzero_in) >= 20:
                fit = powerlaw.Fit(nonzero_in, discrete=True, verbose=False)
                alpha_in = round(fit.power_law.alpha, 3)
                R, p = fit.distribution_compare('power_law', 'exponential')
                pl_better_in = bool(R > 0)   # R>0 → power_law wins
            if len(nonzero_out) >= 20:
                fit = powerlaw.Fit(nonzero_out, discrete=True, verbose=False)
                alpha_out = round(fit.power_law.alpha, 3)
                R, p = fit.distribution_compare('power_law', 'exponential')
                pl_better_out = bool(R > 0)
    except Exception:
        pass

    # ── PageRank validity guard ───────────────────────────────────────────────
    # GUARD: PageRank is meaningful only when the graph is reasonably connected.
    # On 87%-disconnected graphs (mGBA), isolated nodes all receive the base
    # teleportation mass (1-α)/N ≈ 0.00005 — indistinguishable from each other.
    # Flag when >60% of nodes have no in-edges (likely meaningless for most nodes).
    n_no_in = sum(1 for v in va_set if G.in_degree(v) == 0)
    pagerank_valid = (n_no_in / max(len(va_set), 1)) < 0.60

    # ── Annotate per-function ─────────────────────────────────────────────────
    # pr_bet_div: PageRank − betweenness (both normalized to [0,1] range).
    #   > 0  (authority sink): high prestige, not on shortest paths.
    #          Pattern: utility functions everything depends on but don't bridge subgraphs.
    #          Examples: security_check_cookie, RtlFreeHeap.
    #   < 0  (flow bridge):    low prestige, critical path bottleneck.
    #          Pattern: thin connector between major subsystems; easy to miss, hard to remove.
    #   ≈ 0  (balanced):       prestige matches structural position.
    pr_max  = max(pr.values(),     default=1.0) or 1.0
    bet_max = max(bet_nx.values(), default=1.0) or 1.0

    for f in functions:
        va  = f["va"]
        pr_n  = pr.get(va, 0.0)  / pr_max
        bet_n = bet_nx.get(va, 0.0) / bet_max
        f["pagerank"]      = round(pr.get(va, 0.0), 8)
        f["hits_authority"] = round(_hits_auth.get(va, 0.0), 8)  # high = utility callee
        f["hits_hub"]       = round(_hits_hubs.get(va, 0.0), 8)  # high = calls utilities
        f["scc_size"]      = va_to_scc_size.get(va, 1)
        f["scc_rank"]      = va_to_scc_rank.get(va, 0)
        f["in_degree_nx"]  = G.in_degree(va)
        f["out_degree_nx"] = G.out_degree(va)
        f["pr_bet_div"]    = round(pr_n - bet_n, 4)  # + = authority sink; - = flow bridge

    # ── Binary-level summary ──────────────────────────────────────────────────
    largest_scc = max((len(s) for s in sccs), default=0)

    # SCC size histogram — human code pattern: almost all size-1, small tail
    scc_sizes = [len(s) for s in sccs]
    scc_hist  = {
        "size_1":    sum(1 for s in scc_sizes if s == 1),
        "size_2":    sum(1 for s in scc_sizes if s == 2),
        "size_3_5":  sum(1 for s in scc_sizes if 3 <= s <= 5),
        "size_6_20": sum(1 for s in scc_sizes if 6 <= s <= 20),
        "size_21p":  sum(1 for s in scc_sizes if s > 20),
    }

    # DAG depth histogram — where do functions sit in topological order?
    scc_ranks   = [va_to_scc_rank.get(va, 0) for va in va_set]
    max_dag_depth = max(scc_ranks, default=0)
    dag_depth_hist = {
        "d0_1":  sum(1 for r in scc_ranks if r <= 1),
        "d2_4":  sum(1 for r in scc_ranks if 2 <= r <= 4),
        "d5_9":  sum(1 for r in scc_ranks if 5 <= r <= 9),
        "d10p":  sum(1 for r in scc_ranks if r >= 10),
        "max":   max_dag_depth,
    }

    # Top authority sinks (high PR, low betweenness) — the transitive infrastructure
    sinks = sorted(va_set, key=lambda v: -functions[0].get("pr_bet_div", 0))
    # Recompute from f dicts since we just annotated
    fn_pr_bet = {f["va"]: f.get("pr_bet_div", 0) for f in functions}
    top_sinks  = sorted(va_set, key=lambda v: -fn_pr_bet.get(v, 0))[:5]
    top_bridges = sorted(va_set, key=lambda v: fn_pr_bet.get(v, 0))[:5]
    sink_names   = [fn_by_va[v]["name"] for v in top_sinks   if v in fn_by_va]
    bridge_names = [fn_by_va[v]["name"] for v in top_bridges if v in fn_by_va]

    top5_pr    = sorted(pr.items(), key=lambda x: -x[1])[:5]
    top5_names = [fn_by_va[va]["name"] for va, _ in top5_pr if va in fn_by_va]

    return {
        # ── scale ──────────────────────────────────────────────────────────
        "n_functions":          len(functions),
        "n_edges":              G.number_of_edges(),
        # ── size distribution ──────────────────────────────────────────────
        "size_p25":             _percentile(sizes, 25),
        "size_p50":             _percentile(sizes, 50),
        "size_p75":             _percentile(sizes, 75),
        "size_p95":             _percentile(sizes, 95),
        "size_gini":            size_gini,
        "monolith_count":       monolith_cnt,   # functions >= 1000 instructions
        "tiny_count":           tiny_cnt,        # functions < 10 instructions
        # ── instruction class mix (pseudocode-derived, binary fingerprint) ──
        "dominant_class_dist":  dict(dom_classes),
        # ── SCC structure ──────────────────────────────────────────────────
        "n_sccs":               len(sccs),
        "largest_scc_size":     largest_scc,
        "scc1_fraction":        round(scc_hist["size_1"] / max(len(sccs), 1), 3),
        "scc_size_hist":        scc_hist,
        # ── DAG topology ───────────────────────────────────────────────────
        "dag_depth_hist":       dag_depth_hist,
        "max_dag_depth":        max_dag_depth,
        # ── degree distribution ────────────────────────────────────────────
        "degree_entropy_in":    round(H_in,  3),
        "degree_entropy_out":   round(H_out, 3),
        "in_degree_p25":        _percentile(in_degrees, 25),
        "in_degree_p50":        _percentile(in_degrees, 50),
        "in_degree_p75":        _percentile(in_degrees, 75),
        "in_degree_p95":        _percentile(in_degrees, 95),
        "out_degree_p25":       _percentile(out_degrees, 25),
        "out_degree_p50":       _percentile(out_degrees, 50),
        "out_degree_p75":       _percentile(out_degrees, 75),
        "out_degree_p95":       _percentile(out_degrees, 95),
        "powerlaw_alpha_in":      alpha_in,
        "powerlaw_alpha_out":     alpha_out,
        "pl_better_than_exp_in":  pl_better_in,   # False → α unreliable
        "pl_better_than_exp_out": pl_better_out,
        # ── coupling ───────────────────────────────────────────────────────
        "reciprocal_edge_frac": round(recip_frac, 4),
        # ── validity guards ────────────────────────────────────────────────
        "pagerank_valid":        pagerank_valid,
        "compute_ratio_warning": dom_classes.get("COMPUTE", 0) / max(len(functions), 1) > 0.75,
        # ── constant profile (binary-level) ────────────────────────────────
        "known_gap_count":      sum(1 for f in functions if f.get("fmt_str_class") == "KNOWN_GAP"),
        "trap_handler_count":   sum(1 for f in functions if f.get("fmt_str_class") == "TRAP_HANDLER"),
        "ntstatus_fn_count":    sum(1 for f in functions if f.get("ntstatus_frac", 0) > 0.05),
        "mmio_dispatch_count":  sum(1 for f in functions if f.get("dominant_class") == "MMIO_DISPATCH"),
        "struct_heavy_count":   sum(1 for f in functions if f.get("struct_cluster", 0) > 0.6),
        "high_hwaddr_count":    sum(1 for f in functions if f.get("range_hwaddr", 0) >= 3),
        # ── prestige ───────────────────────────────────────────────────────
        "pagerank_top5":        top5_names,
        "authority_sinks_top5": sink_names,    # high PR, low betweenness
        "flow_bridges_top5":    bridge_names,  # low PR, high betweenness
    }


def print_networkx_summary(summary: dict) -> None:
    """Print the binary-level networkx metrics summary."""
    if "error" in summary:
        print(f"[nx] {summary['error']}")
        return

    s = summary
    print(f"\nNETWORKX METRICS SUMMARY")
    print(f"  Scale:      {s['n_functions']} functions  {s['n_edges']} edges")

    # SCC structure
    sh = s.get("scc_size_hist", {})
    print(f"  SCC:        {s['n_sccs']} components  largest={s['largest_scc_size']}"
          f"  acyclic={s['scc1_fraction']:.1%}")
    print(f"  SCC hist:   size1={sh.get('size_1',0)}  size2={sh.get('size_2',0)}"
          f"  size3-5={sh.get('size_3_5',0)}  size6-20={sh.get('size_6_20',0)}"
          f"  size21+={sh.get('size_21p',0)}")

    # DAG depth
    dh = s.get("dag_depth_hist", {})
    print(f"  DAG depth:  0-1={dh.get('d0_1',0)}  2-4={dh.get('d2_4',0)}"
          f"  5-9={dh.get('d5_9',0)}  10+={dh.get('d10p',0)}  max={dh.get('max',0)}")

    # Degree distribution
    print(f"  In-degree:  H={s['degree_entropy_in']:.3f}"
          f"  p25={s['in_degree_p25']}  p50={s['in_degree_p50']}"
          f"  p75={s['in_degree_p75']}  p95={s['in_degree_p95']}")
    print(f"  Out-degree: H={s['degree_entropy_out']:.3f}"
          f"  p25={s['out_degree_p25']}  p50={s['out_degree_p50']}"
          f"  p75={s['out_degree_p75']}  p95={s['out_degree_p95']}")
    α_in, α_out = s.get("powerlaw_alpha_in"), s.get("powerlaw_alpha_out")
    pl_ok_in  = s.get("pl_better_than_exp_in",  None)
    pl_ok_out = s.get("pl_better_than_exp_out", None)
    if α_in or α_out:
        in_str  = f"{α_in}{'✓' if pl_ok_in  else '?' if pl_ok_in  is None else '✗'}"
        out_str = f"{α_out}{'✓' if pl_ok_out else '?' if pl_ok_out is None else '✗'}"
        print(f"  Power-law α: in={in_str}  out={out_str}"
              f"  (✓=better than exp; ✗=exp fits better→α unreliable; typical: 2-3)")

    # Validity warnings
    if not s.get("pagerank_valid", True):
        print(f"  [WARN] pagerank_valid=False: >60% nodes disconnected."
              f" PageRank scores are near-uniform for isolated nodes.")
    if s.get("compute_ratio_warning", False):
        print(f"  [WARN] compute_ratio >75%: likely overcounting pointer arithmetic."
              f" Calibrate pure_arith regex with benchmark data.")

    # Coupling
    recip = s.get("reciprocal_edge_frac", 0)
    recip_label = ("low — healthy one-way calls" if recip < 0.05
                   else "moderate — some mutual deps" if recip < 0.15
                   else "HIGH — circular deps or obfuscation")
    print(f"  Reciprocal edges: {recip:.1%}  [{recip_label}]")

    # Prestige
    # Size distribution
    print(f"  Fn sizes:   p25={s.get('size_p25',0)}  p50={s.get('size_p50',0)}"
          f"  p75={s.get('size_p75',0)}  p95={s.get('size_p95',0)}"
          f"  gini={s.get('size_gini',0):.3f}"
          f"  monoliths(1k+)={s.get('monolith_count',0)}"
          f"  tiny(<10)={s.get('tiny_count',0)}")
    # Instruction + constant class distribution
    dc = s.get("dominant_class_dist", {})
    if dc:
        total = sum(dc.values()) or 1
        parts = "  ".join(f"{k}={v}({100*v//total}%)" for k, v in sorted(dc.items(), key=lambda x: -x[1]))
        print(f"  Instr mix:  {parts}")
    ns = s.get("ntstatus_fn_count", 0)
    mm = s.get("mmio_dispatch_count", 0)
    sh = s.get("struct_heavy_count", 0)
    hw = s.get("high_hwaddr_count", 0)
    print(f"  Const profile: struct_heavy={sh}  ntstatus_fns={ns}"
          f"  mmio_dispatch={mm}  hw_addr_fns={hw}")
    print(f"  Top PageRank:    {', '.join(s.get('pagerank_top5', []))}")
    print(f"  Authority sinks: {', '.join(s.get('authority_sinks_top5', []))}"
          f"  [high PR, low betweenness — transitive infrastructure]")
    print(f"  Flow bridges:    {', '.join(s.get('flow_bridges_top5', []))}"
          f"  [low PR, high betweenness — structural connectors]")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Compute call graph topology metrics for a calltree JSON")
    ap.add_argument("path", help="Path to calltree.json")
    ap.add_argument("--top", type=int, default=0, metavar="N",
                    help="Show only top N functions by graph_rank")
    ap.add_argument("--annotate", action="store_true",
                    help="Write metrics back into the JSON file")
    ap.add_argument("--components", action="store_true",
                    help="Show WCC component breakdown (density, clustering, role)")
    ap.add_argument("--nx", action="store_true",
                    help="Show NetworkX metrics: SCC, PageRank, degree entropy, power-law α")
    ap.add_argument("--extra-seeds", metavar="VAs", dest="extra_seeds",
                    help="Comma-separated hex VAs to treat as additional seeds "
                         "(e.g. from heap scan or dynamic dispatch discovery). "
                         "Or a path to a JSON file with a list of VA strings.")
    opts = ap.parse_args()

    with open(opts.path, encoding="utf-8") as f:
        data = json.load(f)

    fns = data["functions"]
    va_set = {f["va"] for f in fns}

    # Extract seeds. Priority:
    # 1. function_seeds that actually appear in calltree (coordinate-matched)
    # 2. Named non-FUN_* exports (survive stripping, coordinate-independent)
    # 3. depth=0 functions (fallback)
    raw_seeds   = {v for v in data.get("function_seeds", []) if v and v != "0x0"}
    valid_seeds = raw_seeds & va_set
    seed_vas    = valid_seeds if valid_seeds else None

    # --extra-seeds: inject runtime-discovered VAs (heap scan, dispatch table scan)
    if opts.extra_seeds:
        import os
        extra_raw = opts.extra_seeds
        if os.path.isfile(extra_raw):
            with open(extra_raw, encoding="utf-8") as ef:
                extra_list = json.load(ef)
        else:
            extra_list = [v.strip() for v in extra_raw.split(",") if v.strip()]
        extra_norm = set()
        for v in extra_list:
            try:
                extra_norm.add(hex(int(v, 16)))
            except ValueError:
                extra_norm.add(v)
        added = extra_norm & va_set
        if seed_vas is None:
            seed_vas = added
        else:
            seed_vas = seed_vas | added
        print(f"[extra-seeds] +{len(added)} dynamic seeds injected "
              f"({len(extra_norm)-len(added)} not in calltree)")

    annotate_calltree(fns, seed_vas=seed_vas)
    if getattr(opts, "nx", False):
        nx_sum = getattr(annotate_calltree, "_last_nx_summary", {})
        print_networkx_summary(nx_sum)
    if getattr(opts, "components", False):
        comps = getattr(annotate_calltree, "_last_components", [])
        print_components(comps)
    print_ranked(fns, top_n=opts.top)

    if opts.annotate:
        with open(opts.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\nAnnotated {len(fns)} functions → {opts.path}")
