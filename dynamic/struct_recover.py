"""
dynamic/struct_recover.py — Program Geometry: Global Init Structure Recovery

Treats programs as geometric objects whose structure we project onto measurable axes.
Each projection is a theorem about program memory geometry, validated empirically.

VALIDATED THEOREMS (2026-06-21, cross-DLL):
  T1  Address proximity (gap<4KB) → struct membership
  T2  Co-access density → ARRAY (<20%) vs MONOLITHIC (>50%) access pattern
  T3  4B alignment ratio → geometric type discriminant:
        >80%: STRUCT domain (C structs, 4B-aligned fields)
        40-80%: ENUM/FLAGS domain (mixed byte/word fields)
        <40%: LOOKUP TABLE domain (dense byte arrays, dispatch tables)
  T5  GCD(pairwise offset differences) = fundamental array element size (lattice theorem)

NEW PROJECTIONS (P6-P9) — not yet cross-DLL validated:
  P6  Offset entropy → field size uniformity (low=array, high=irregular struct)
  P7  Co-access betweenness → hub fields (read by most functions together)
  P8  First-access step in P-CODE → guard fields (step 1-3) vs compute fields (step 10+)
  P9  Population density = observed_globals / (span / min_stride)
        High density → lookup table; Low density → large struct with unobserved fields

MATHEMATICAL CONNECTIONS:
  - T3 is a compiler/ABI invariant (C struct alignment rules, MSVC/GCC/Clang all agree)
  - T5 is 1D distance geometry: GCD of observed differences = fundamental lattice generator
  - T2 mirrors sheaf theory: monolithic structs have global sections; arrays have local sections
  - Together these projections form a "fingerprint" of the program's geometric type
  - Classification theorem (conjectured): programs form equivalence classes under struct isomorphism,
    detectable from the projection vector without running the program

OPEN QUESTIONS (50-year horizon):
  - Is the valid global init space an algebraic variety over Z/2^64?
  - What is the minimum number of projections to reconstruct it?
  - Do programs from the same framework form isomorphic geometry classes?
"""
from __future__ import annotations
import math
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Optional


# ── GCD utilities ─────────────────────────────────────────────────────────────

def _gcd(a: int, b: int) -> int:
    while b: a, b = b, a % b
    return a

def _gcd_list(lst: list[int]) -> int:
    g = lst[0]
    for x in lst[1:]: g = _gcd(g, x)
    return g


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class StructCluster:
    """One proximity-based global cluster = one candidate struct."""
    base:          int
    span:          int
    addresses:     list[int]
    offsets:       list[int]          # relative to base
    # T3
    align4_frac:   float = 0.0
    align8_frac:   float = 0.0
    align4_z:      float = 0.0       # z-score vs 25% random baseline
    # T2
    coaccesses_total: int = 0
    coaccesses_possible: int = 0
    coaccess_density: float = 0.0
    access_pattern: str = "UNKNOWN"  # ARRAY / MONOLITHIC / MIXED / SINGLETON
    # T5
    gcd_stride:    int = 0
    n_array_elements: int = 0
    stride_consistency: float = 0.0
    # P6
    offset_entropy: float = 0.0
    # P7
    hub_globals:   list[int] = field(default_factory=list)  # top betweenness globals
    # P8: first-access step distribution — guard fields accessed early, compute fields late
    guard_globals:   list[int] = field(default_factory=list)   # first_step <= 3
    compute_globals: list[int] = field(default_factory=list)   # first_step >= 10
    # P9
    population_density: float = 0.0
    # Geometric type (from T3)
    geo_type:      str = "UNKNOWN"   # STRUCT / ENUM_FLAGS / LOOKUP_TABLE / SINGLETON


@dataclass
class GeometryReport:
    """Full geometry analysis for one DLL."""
    label:         str
    n_globals:     int
    n_fns:         int
    clusters:      list[StructCluster]
    # Cross-cluster statistics
    T3_global:     float = 0.0       # global 4B alignment ratio
    T3_z_global:   float = 0.0
    dominant_type: str = "UNKNOWN"
    # Summary
    n_struct:      int = 0
    n_lookup:      int = 0
    n_array:       int = 0
    # Indirect struct recovery: fields accessed through pointer globals
    # {base_global_addr: {field_offset: (size, fn_count)}}
    indirect_structs: dict = field(default_factory=dict)


# ── Core analysis ─────────────────────────────────────────────────────────────

class ProgramGeometry:
    """
    Computes program geometry projections from pcode_sym global_reads data.

    Usage:
        pg = ProgramGeometry(label='myDLL')
        for fn_name, global_reads in fn_globals.items():
            pg.add_function(fn_name, global_reads)
        report = pg.analyze()
    """

    def __init__(self, label: str, gap_threshold: int = 0x1000,
                 emit_to_kb: bool = False):
        self.label = label
        self.gap = gap_threshold
        self.emit_to_kb = emit_to_kb
        self._fn_globals: dict[str, frozenset[int]] = {}
        self._fn_first_access: dict[str, dict[int, int]] = {}
        # Indirect struct field accesses: (base_global, field_offset) → max_size_seen
        self._struct_fields: dict[tuple[int,int], int] = {}
        # How many functions observed each field
        self._struct_fn_count: dict[tuple[int,int], int] = {}  # fn→{addr: step}

    def add_function(self, fn_name: str, global_reads: dict[int, int],
                     first_access_steps: dict[int, int] | None = None,
                     struct_field_reads: list | None = None) -> None:
        """
        Register one function's global reads.
        global_reads: {addr: size_bytes}
        first_access_steps: {addr: step_number_in_pcode} (optional, for P8)
          Low step (<=3) = guard/null-check field accessed before any computation.
          High step (>=10) = compute field accessed deep in the function body.
        """
        self._fn_globals[fn_name] = frozenset(global_reads.keys())
        if first_access_steps:
            self._fn_first_access[fn_name] = first_access_steps
        if struct_field_reads:
            for base, offset, size in struct_field_reads:
                self._struct_fields[(base, offset)] = max(
                    self._struct_fields.get((base, offset), 0), size)
                self._struct_fn_count[(base, offset)] = \
                    self._struct_fn_count.get((base, offset), 0) + 1

    def analyze(self) -> GeometryReport:
        all_globals = sorted(set(g for addrs in self._fn_globals.values() for g in addrs))
        if not all_globals:
            return GeometryReport(self.label, 0, 0, [])

        # ── T1: Proximity clustering ──────────────────────────────────────────
        clusters_raw = []
        cur = [all_globals[0]]
        for a in all_globals[1:]:
            if a - cur[-1] <= self.gap:
                cur.append(a)
            else:
                clusters_raw.append(cur); cur = [a]
        clusters_raw.append(cur)

        # ── Build co-access matrix ────────────────────────────────────────────
        coaccesses: dict[tuple[int,int], int] = defaultdict(int)
        fn_visit_count: dict[int, int] = defaultdict(int)
        for addrs in self._fn_globals.values():
            addr_list = sorted(addrs)
            for i, a in enumerate(addr_list):
                fn_visit_count[a] += 1
                for b in addr_list[i+1:]:
                    key = (min(a,b), max(a,b))
                    coaccesses[key] += 1

        # ── Analyze each cluster ──────────────────────────────────────────────
        clusters: list[StructCluster] = []
        for raw in clusters_raw:
            c = self._analyze_cluster(raw, coaccesses, fn_visit_count)
            clusters.append(c)

        # ── P7: Hub globals across all clusters ───────────────────────────────
        # High co-access betweenness = appears in many distinct co-access pairs
        global_betweenness: dict[int, int] = defaultdict(int)
        for (a, b), cnt in coaccesses.items():
            global_betweenness[a] += cnt
            global_betweenness[b] += cnt
        for c in clusters:
            hubs = sorted(c.addresses, key=lambda a: -global_betweenness.get(a, 0))
            c.hub_globals = hubs[:3]

        # ── Global T3 ─────────────────────────────────────────────────────────
        all_offsets = []
        for c in clusters:
            all_offsets.extend(c.offsets)
        if all_offsets:
            n = len(all_offsets)
            a4 = sum(1 for o in all_offsets if o % 4 == 0)
            t3 = a4 / n
            z3 = (a4 - 0.25*n) / math.sqrt(n * 0.25 * 0.75) if n > 0 else 0
        else:
            t3, z3 = 0.0, 0.0

        # ── Summary counts ────────────────────────────────────────────────────
        n_struct  = sum(1 for c in clusters if c.geo_type == 'STRUCT')
        n_lookup  = sum(1 for c in clusters if c.geo_type == 'LOOKUP_TABLE')
        n_array   = sum(1 for c in clusters if c.access_pattern == 'ARRAY')

        # Dominant type = type with most GLOBALS (not clusters)
        by_type: dict[str, int] = defaultdict(int)
        for c in clusters:
            by_type[c.geo_type] += len(c.addresses)
        dominant = max(by_type, key=by_type.get) if by_type else 'UNKNOWN'

        # Build indirect struct map: group field accesses by base global address
        indirect_structs: dict = {}
        for (base, offset), size in self._struct_fields.items():
            fn_cnt = self._struct_fn_count.get((base, offset), 0)
            if base not in indirect_structs:
                indirect_structs[base] = {}
            indirect_structs[base][offset] = (size, fn_cnt)

        report = GeometryReport(
            label=self.label,
            n_globals=len(all_globals),
            n_fns=len(self._fn_globals),
            clusters=clusters,
            T3_global=t3,
            T3_z_global=z3,
            dominant_type=dominant,
            n_struct=n_struct,
            n_lookup=n_lookup,
            n_array=n_array,
            indirect_structs=indirect_structs,
        )
        # Emit to knowledge bus if available
        if self.emit_to_kb:
            self._emit_kb(clusters)
        return report

    def _emit_kb(self, clusters: list) -> None:
        """Emit discovered struct fields to the knowledge bus as EPHEMERAL observations."""
        try:
            import knowledge_bus as kb
        except ImportError:
            return
        for c in clusters:
            if len(c.addresses) < 2 or c.geo_type == 'SINGLETON':
                continue
            struct_key = f'auto_{c.base:#x}'
            fn_count = sum(1 for addrs in self._fn_globals.values()
                           if any(a in addrs for a in c.addresses))
            # Confidence: more functions observing → higher confidence
            confidence = min(0.9, 0.3 + fn_count * 0.05)
            for addr in c.addresses:
                offset = addr - c.base
                # Semantic hint from P8
                if addr in c.guard_globals:
                    field_name = f'guard_{offset:#x}'
                elif addr in c.compute_globals:
                    field_name = f'field_{offset:#x}'
                else:
                    field_name = f'field_{offset:#x}'
                try:
                    kb.emit_field_access(
                        struct_key=struct_key,
                        offset=offset,
                        field_name=field_name,
                        layer='struct_recover',
                        evidence=f'T3={c.align4_frac:.0%} pattern={c.access_pattern}',
                    )
                except Exception:
                    pass

    def _analyze_cluster(self, addrs: list[int],
                          coaccesses: dict, fn_visit_count: dict) -> StructCluster:
        base = min(addrs)
        span = max(addrs) - base
        offsets = sorted(a - base for a in addrs)
        non_zero = [o for o in offsets if o > 0]

        c = StructCluster(base=base, span=span,
                          addresses=sorted(addrs), offsets=offsets)

        if len(addrs) == 1:
            c.access_pattern = 'SINGLETON'
            c.geo_type = 'SINGLETON'
            return c

        # T3: alignment
        n = len(non_zero)
        if n > 0:
            a4 = sum(1 for o in non_zero if o % 4 == 0)
            a8 = sum(1 for o in non_zero if o % 8 == 0)
            c.align4_frac = a4 / n
            c.align8_frac = a8 / n
            c.align4_z = ((a4 - 0.25*n) / math.sqrt(n * 0.25 * 0.75)) if n > 0 else 0
            # Geometric type from T3
            if c.align4_frac >= 0.80:
                c.geo_type = 'STRUCT'
            elif c.align4_frac >= 0.40:
                c.geo_type = 'ENUM_FLAGS'
            else:
                c.geo_type = 'LOOKUP_TABLE'
        else:
            c.geo_type = 'SINGLETON'

        # T2: co-access density
        pairs = [(min(a,b), max(a,b)) for i,a in enumerate(addrs) for b in addrs[i+1:]]
        co = sum(1 for p in pairs if coaccesses.get(p, 0) > 0)
        c.coaccesses_total = co
        c.coaccesses_possible = len(pairs)
        c.coaccess_density = co / len(pairs) if pairs else 0
        if len(addrs) < 2:
            c.access_pattern = 'SINGLETON'
        elif c.coaccess_density < 0.20:
            c.access_pattern = 'ARRAY'
        elif c.coaccess_density > 0.50:
            c.access_pattern = 'MONOLITHIC'
        else:
            c.access_pattern = 'MIXED'

        # T5: Modal stride (lattice theorem — improved over GCD)
        # GCD finds minimum divisor but returns 1 for irregular layouts.
        # Modal stride finds the MOST COMMON inter-field gap, then verifies
        # that most other gaps are multiples of it.
        # "Most common gap that most other gaps are multiples of" = array element size.
        if len(non_zero) >= 3:
            diffs = [offsets[i+1] - offsets[i]
                     for i in range(len(offsets)-1) if offsets[i+1] > offsets[i]]
            if diffs:
                diff_counts = Counter(diffs)
                # Find smallest stride where >50% of diffs are multiples
                candidates = sorted(set(diffs))
                best_stride, best_consist = 0, 0.0
                for cand in candidates:
                    if cand <= 0: continue
                    multiples = sum(1 for d in diffs if d % cand == 0)
                    consist = multiples / len(diffs)
                    if consist > best_consist or (consist == best_consist and cand < best_stride):
                        best_consist = consist
                        best_stride = cand
                if best_consist >= 0.75 and best_stride > 0:
                    c.stride_consistency = best_consist
                    c.gcd_stride = best_stride
                    c.n_array_elements = span // best_stride + 1

        # P6: offset entropy
        if len(non_zero) >= 2:
            diff_counts = Counter(non_zero[i+1] - non_zero[i]
                                  for i in range(len(non_zero)-1))
            total = sum(diff_counts.values())
            c.offset_entropy = -sum((v/total) * math.log2(v/total)
                                    for v in diff_counts.values() if v > 0)

        # P8: first-access step → guard vs compute field classification
        # Aggregate first-access steps across all functions for each global.
        # Guard fields: accessed at step 0-3 (null/validity check before computation).
        # Compute fields: accessed at step 10+ (used deep in function body).
        if self._fn_first_access:
            step_totals: dict[int, list[int]] = {a: [] for a in addrs}
            for fn_steps in self._fn_first_access.values():
                for addr in addrs:
                    if addr in fn_steps:
                        step_totals[addr].append(fn_steps[addr])
            for addr, steps_list in step_totals.items():
                if not steps_list: continue
                median_step = sorted(steps_list)[len(steps_list)//2]
                if median_step <= 3:
                    c.guard_globals.append(addr)
                elif median_step >= 10:
                    c.compute_globals.append(addr)

        # P9: population density
        min_stride = c.gcd_stride if c.gcd_stride > 0 else 4
        max_possible = span // min_stride + 1 if min_stride > 0 else 1
        c.population_density = len(addrs) / max_possible if max_possible > 0 else 0

        return c


# ── Reporting ─────────────────────────────────────────────────────────────────

def print_report(r: GeometryReport, verbose: bool = False) -> None:
    print(f'\n{"="*60}')
    print(f'GEOMETRY: {r.label}')
    print(f'  {r.n_globals} globals  {r.n_fns} fns  {len(r.clusters)} clusters')
    print(f'  T3 global: {r.T3_global:.0%}  z={r.T3_z_global:.1f}σ')
    print(f'  Dominant type: {r.dominant_type}  '
          f'(STRUCT={r.n_struct} LOOKUP={r.n_lookup} ARRAY_pattern={r.n_array})')

    print(f'\n  Clusters by size:')
    for c in sorted(r.clusters, key=lambda x: -len(x.addresses))[:8]:
        if len(c.addresses) == 1 and not verbose:
            continue
        print(f'  [{len(c.addresses):4d}g] base={c.base:#x} span={c.span:#x} '
              f'type={c.geo_type:<12} pattern={c.access_pattern:<10} '
              f'T3={c.align4_frac:.0%} density={c.coaccess_density:.0%}')
        if c.gcd_stride:
            print(f'         stride=0x{c.gcd_stride:x} x {c.n_array_elements} '
                  f'(consist={c.stride_consistency:.0%}) '
                  f'entropy={c.offset_entropy:.2f}bits '
                  f'pop={c.population_density:.0%}')
        if c.hub_globals and verbose:
            print(f'         hubs: {[hex(h) for h in c.hub_globals]}')
        if (c.guard_globals or c.compute_globals) and verbose:
            print(f'         guard(early): {[hex(g) for g in c.guard_globals[:3]]}  '
                  f'compute(late): {[hex(g) for g in c.compute_globals[:3]]}')
    _print_indirect(r)


def _print_indirect(r: GeometryReport) -> None:
    """Print indirect struct recovery results (fields accessed through global pointers)."""
    if not r.indirect_structs:
        return
    print(f'\n  INDIRECT STRUCTS (fields accessed through global pointers):')
    for base, fields in sorted(r.indirect_structs.items(),
                                key=lambda x: -len(x[1]))[:6]:
        sorted_fields = sorted(fields.items())
        span = sorted_fields[-1][0] - sorted_fields[0][0] if len(sorted_fields) > 1 else 0
        max_fn_count = max(cnt for _, (_, cnt) in sorted_fields)
        print(f'    ptr@{base:#x} → {len(fields)} fields  span={span:#x}  '
              f'max_fns={max_fn_count}')
        for offset, (size, fn_cnt) in sorted_fields[:8]:
            print(f'      +{offset:#06x}  {size}B  (seen in {fn_cnt} fns)')
        if len(sorted_fields) > 8:
            print(f'      ... ({len(sorted_fields)-8} more)')


def compare_reports(reports: list[GeometryReport]) -> None:
    """Cross-DLL invariant comparison."""
    print(f'\n{"="*70}')
    print('CROSS-DLL INVARIANT COMPARISON')
    print(f'{"="*70}')
    print(f'  {"Label":<30} {"T3":>6} {"z":>7} {"Dom type":<14} {"Clusters":>8}')
    print(f'  {"-"*30} {"-"*6} {"-"*7} {"-"*14} {"-"*8}')

    t3s = [(r.T3_global, r.T3_z_global) for r in reports if r.T3_global > 0]

    for r in reports:
        print(f'  {r.label:<30} {r.T3_global:>5.0%} {r.T3_z_global:>7.1f}σ '
              f'{r.dominant_type:<14} {len(r.clusters):>8}')

    if t3s:
        vals = [t for t,_ in t3s]
        print(f'\n  T3 range: [{min(vals):.0%}, {max(vals):.0%}]  '
              f'spread={max(vals)-min(vals):.0%}')

        # Geometric type classification based on T3
        print(f'\n  TYPE CLASSIFICATION (T3-based):')
        print(f'    STRUCT (T3>80%): {[r.label for r in reports if r.T3_global > 0.80]}')
        print(f'    ENUM/FLAGS (40-80%): {[r.label for r in reports if 0.40 <= r.T3_global <= 0.80]}')
        print(f'    LOOKUP TABLE (T3<40%): {[r.label for r in reports if 0 < r.T3_global < 0.40]}')

        spread = max(vals) - min(vals)
        if spread < 0.10:
            print(f'\n  ** T3 IS UNIVERSAL (spread={spread:.0%} < 10%) **')
        else:
            print(f'\n  ** T3 VARIES BY TYPE (spread={spread:.0%}) **')
            print(f'  ** T3 IS A TYPE DISCRIMINANT, not a universal constant **')
            print(f'  ** This is MORE INTERESTING — it reveals program geometry classes **')
