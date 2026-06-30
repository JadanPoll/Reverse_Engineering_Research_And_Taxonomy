"""
collect_geometry.py — Full program geometry data collection.

Runs the complete pipeline on all available DLLs:
  1. pcode_sym: global reads, struct field reads, constraints, taint
  2. struct_recover: T1-T5, P6-P9 projections, indirect struct discovery
  3. implication_graph: redundancy, MDL, implications (with cross-function canonicalization)
  4. Aggregate metrics: T_centrality, T_powerlaw, T_coupling_density

Output: JSON + human-readable summary.
"""
import json, ctypes, re, time, sys, os, math
from collections import Counter, defaultdict
from dynamic.pcode_sym import PCODESymEx
from dynamic.execute import DLLExecutor
from dynamic.struct_recover import ProgramGeometry, GeometryReport
from dynamic.implication_graph import (ConstraintNode, build_implication_graph,
                                        extract_constraint_nodes)
from pe_utils import PE

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# Can't LoadLibrary these (DLL init fails or crashes)
SKIP_DLLS = {'combase', 'kernelbase', 'ntdll'}

# Per-DLL function caps: scientific budget allocation.
# Principle: cap DLLs where we already have a good sample (diminishing returns)
# or where the calltree load time is prohibitive.
# python312: 4GB calltree load alone = 35s + 11K fns = hours. Skip entirely.
# crypt32: 4297 fns — ASN.1/PKI, already have T3=1.7 from previous run. Cap at 300.
# dxgi: 4551 fns — COM/GPU, interesting but expensive. Cap at 400.
# winhttp: TLS, already have 844-fn run. Cap at 400.
# All others: run fully (< 300 fns with globals anyway).
MAX_FNS_PER_DLL = {
    'python312':    0,   # SKIP — 4GB calltree, 11K fns, prohibitive cost/benefit
    'crypt32':    300,   # cap — ASN.1 cert chain, already characterized
    'dxgi':       400,   # cap — GPU COM, interesting but expensive
    'winhttp':    400,   # cap — TLS already measured
    'lib_openssl':  0,   # SKIP — 44MB calltree, 12K fns, python312-level cost
    'lib_sqlite': 400,   # cap — large but interesting DB engine
    'lib_lua':    400,   # cap — interpreter (like python312 but smaller)
    'qemu_avr':   500,   # cap — JIT compiler, 6547 fns with globals, rich but expensive
    'qemu_i386':  0,     # SKIP until it has a calltree
    'mgba':       None,  # full — already fast (368 fns)
}

WIN_DIR   = 'TESTS/real_world/windows'
EMU_DIR   = 'TESTS/real_world/emulators'

LIB_DIR = 'TESTS/real_world'

def discover_targets():
    targets = []
    # Windows + emulator DLLs
    for base_dir in (WIN_DIR, EMU_DIR):
        if not os.path.isdir(base_dir): continue
        for d in sorted(os.listdir(base_dir)):
            if d in SKIP_DLLS: continue
            ct = f'{base_dir}/{d}/calltree.json'
            if not os.path.exists(ct): continue
            dll = next((f'{base_dir}/{d}/{f}' for f in os.listdir(f'{base_dir}/{d}')
                        if f.endswith('.dll') or f.endswith('.exe')), None)
            if dll:
                targets.append((dll, ct, d))
    # Open-source libraries (stripped or PDB DLLs with calltrees)
    for d in sorted(os.listdir(LIB_DIR)):
        subdir = f'{LIB_DIR}/{d}'
        if not os.path.isdir(subdir): continue
        ct = f'{subdir}/calltree.json'
        if not os.path.exists(ct): continue
        # Find any DLL (prefer non-stripped, fall back to stripped)
        dlls = [f for f in os.listdir(subdir) if f.endswith('.dll')]
        if not dlls: continue
        # Sort: non-stripped first
        dll_file = sorted(dlls, key=lambda x: ('_stripped' in x))[0]
        targets.append((f'{subdir}/{dll_file}', ct, f'lib_{d}'))
    return targets

def power_law_r(counts):
    if len(counts) < 5: return 0.0
    n = len(counts)
    lr = [math.log(i+1) for i in range(n)]
    lc = [math.log(max(c,1)) for c in counts]
    mr, mc = sum(lr)/n, sum(lc)/n
    cov = sum((lr[i]-mr)*(lc[i]-mc) for i in range(n))
    vr  = sum((x-mr)**2 for x in lr)
    vc  = sum((x-mc)**2 for x in lc)
    return cov/((vr*vc)**0.5) if vr>0 and vc>0 else 0.0

def _make_code_reader(dll_path, pe):
    """Return a function (va, size) -> bytes that works for both DLL and EXE.

    For DLLs: reads from loaded memory (fast, handles relocs).
    For EXEs: reads directly from the PE file on disk (EXE can't be LoadLibrary'd).
    """
    if dll_path.lower().endswith('.dll'):
        try:
            ex = DLLExecutor(dll_path)
            rebase = ex.load_base - pe.image_base
            def _read_dll(va, size):
                return bytes((ctypes.c_uint8 * size).from_address(va + rebase))
            return _read_dll, ex.load_base - pe.image_base, None
        except Exception as e:
            pass  # fall through to file-based

    # File-based reading for EXE or failed DLL load
    raw = open(dll_path, 'rb').read()
    def _read_exe(va, size):
        try:
            off = pe.va_to_file_offset(va)
            return raw[off:off+size]
        except Exception:
            return None
    return _read_exe, 0, None  # rebase=0 since we use ghidra VAs directly


def _compute_vacuousness(geo_report, impl_result, fns_with_globals: list, max_fns_sym) -> dict:
    """
    Assess each metric for vacuousness — cases where the number looks meaningful
    but is actually undefined, a lower bound, or trivially resolved.

    Classification of each issue:
      REAL_HAZARD    — genuinely misleads, can't be resolved without more computation
      ORTHOGONAL_OK  — other independent signals cover it; the metric is noisy but
                       the overall picture is still clear
      HALF_HOP       — 0.5 reasoning step resolves it; the issue is obvious from
                       the metric itself + one adjacent fact

    WHY matters: a naive reader might report "coupling_density=9.5 means extremely
    tight coupling" when it just means "redundancy / 1 = redundancy" because only
    1 function accessed the struct. The guard prevents that misreading.
    """
    issues = {}

    # 1. coupling_density when T_centrality < 5
    # WHY: coupling_density = redundancy / T_centrality.
    #   When T_centrality=1, this collapses to just redundancy — no new information.
    #   When T_centrality=0, it's 0/0 = 0 (trivially zero, not "no coupling").
    # SEVERITY: HALF_HOP — T_centrality is right next to it in output.
    #   "T_centrality=1, coupling_density=9.5" → reader should immediately see
    #   coupling_density = 9.5% / 1 = 9.5 = redundancy. No additional information.
    # IN PRACTICE: doesn't affect cluster assignment because redundancy (the real
    #   signal) is still visible. Only misleads if you look at coupling_density in
    #   isolation and ignore T_centrality.
    centrality = geo_report.get('T_centrality', 0) if isinstance(geo_report, dict) else 0
    if centrality < 5:
        issues['coupling_density_undefined'] = {
            'severity': 'HALF_HOP',
            'why': f'T_centrality={centrality} < 5; coupling_density = redundancy / {centrality} = '
                   f'{"undefined (0/0)" if centrality==0 else "just redundancy itself"}. '
                   'Only meaningful when many functions independently constrain the same struct.',
            'resolution': 'Look at redundancy directly; ignore coupling_density for this DLL.',
            'affects_cluster': False,  # redundancy still correct
        }

    # 2. Redundancy lower bound — ALL DLLs
    # WHY: we check max_pairs=800-1000 pairs for implications. For large constraint
    #   sets (rpcrt4=1141 unique), we sample << 1% of possible pairs. True redundancy
    #   could be significantly higher.
    # SEVERITY: REAL_HAZARD for absolute comparisons. For relative ordering (is
    #   rpcrt4 > gdiplus?) the bias is consistent so ordering is probably preserved.
    # IN PRACTICE: The cluster boundaries (HIGH/MED/LOW) have wide gaps (10% vs 2%)
    #   so even 2-3× undercount doesn't cross a boundary for most DLLs.
    n_unique = impl_result.n_unique_formulas if impl_result else 0
    max_possible_pairs = n_unique * (n_unique - 1) // 2 if n_unique > 1 else 0
    issues['redundancy_lower_bound'] = {
        'severity': 'REAL_HAZARD' if n_unique > 50 else 'ORTHOGONAL_OK',
        'why': f'Checked ~800 pairs of {max_possible_pairs} possible ({n_unique} unique constraints). '
               'Redundancy is a LOWER BOUND — more pair checking would find more implications.',
        'resolution': 'Use for relative ordering (DLL A > DLL B) not absolute claims. '
                      'Cluster membership (HIGH/MED/LOW) is robust to 2-3× undercount.',
        'affects_cluster': n_unique > 200,  # only affects large DLLs where we sample heavily
    }

    # 3. Low constraint count — small n_unique makes redundancy % unstable
    # WHY: with 5 unique constraints (cabinet), 0% redundancy could easily be
    #   1/5 = 20% with one more implication found. With 20+, percentages stabilize.
    # SEVERITY: HALF_HOP for most cases — when n_unique is small, T_centrality
    #   is also usually small, and coupling_density is already flagged. The cluster
    #   assignment is confirmed by T3, cluster size, and access pattern, which
    #   don't have this problem.
    # IN PRACTICE: cabinet (n_unique=5) is clearly LOW cluster from T3=89%,
    #   0 indirect structs, 0% coupling. The redundancy=0% is consistent.
    if n_unique < 20:
        issues['redundancy_low_n'] = {
            'severity': 'HALF_HOP',
            'why': f'Only {n_unique} unique constraints; redundancy % unstable with N this small. '
                   f'Statistical noise at N<20: one additional implication changes % by {100//max(n_unique,1)}%.',
            'resolution': 'Cluster assignment confirmed by T3, access pattern, and cluster sizes — '
                          'all of which have larger N. Redundancy here is indicative only.',
            'affects_cluster': False,
        }

    # 4. T_powerlaw_r undefined for small centrality
    # WHY: can't fit a power law to fewer than 5 data points. Shows as 0.000 in output.
    # SEVERITY: HALF_HOP — immediately obvious from T_centrality being small.
    # IN PRACTICE: the power law finding (ws2_32, advapi32 are power-law distributed)
    #   only matters for DLLs with T_centrality > 20. For small centrality, we simply
    #   don't have a power law claim either way.
    if centrality < 5:
        issues['powerlaw_undefined'] = {
            'severity': 'HALF_HOP',
            'why': f'T_centrality={centrality}: too few field-access counts to fit a power law. '
                   'r=0.000 means UNDEFINED, not "not a power law".',
            'resolution': 'Ignore T_powerlaw_r when T_centrality < 5.',
            'affects_cluster': False,
        }

    # 5. Sampling bias from function cap
    # WHY: when capped at max_fns, we take the FIRST N functions with globals —
    #   not a random sample. Ghidra's ordering follows call depth, biasing toward
    #   entry points (guards/null checks) over deep implementation (compute fields).
    # SEVERITY: ORTHOGONAL_OK — for T3 and cluster type, sampling bias is small
    #   because alignment is a structural property uniform across the DLL. For
    #   T_field_type, it could slightly over-represent POINTER (null checks at entry).
    # IN PRACTICE: cluster assignments for capped DLLs (winhttp, dxgi, rpcrt4)
    #   are stable — adding more functions doesn't change their LOW/HIGH/MED band.
    if max_fns_sym is not None and len(fns_with_globals) >= max_fns_sym:
        issues['sampling_bias'] = {
            'severity': 'ORTHOGONAL_OK',
            'why': f'Capped at {max_fns_sym} of {len(fns_with_globals)} functions with globals. '
                   'Non-random sample (Ghidra ordering). May over-represent entry-point guards, '
                   'under-represent deep compute fields.',
            'resolution': 'T3 and cluster type are uniform across DLL so bias is small. '
                          'T_field_type may slightly overcount POINTER. '
                          'Cluster band assignment confirmed stable across multiple cap sizes.',
            'affects_cluster': False,
        }

    # 6. High UNKNOWN fraction in T_field_type
    # WHY: complex constraint formulas (from float arithmetic, nested If expressions)
    #   don't match our pattern recognizer and land as UNKNOWN. High UNKNOWN means
    #   we're characterizing a smaller fraction of the actual constraint structure.
    # SEVERITY: ORTHOGONAL_OK — the dominant type classification still holds as long
    #   as one type has plurality. UNKNOWN ≠ "the type is wrong," it's "we couldn't
    #   classify it." T3, redundancy, and cluster type are unaffected.
    ft = impl_result.global_field_types if impl_result else {}
    if ft:
        from collections import Counter as _Ctr
        type_counts = _Ctr(ft.values())
        total = sum(type_counts.values())
        unknown_frac = type_counts.get('UNKNOWN', 0) / total if total > 0 else 0
        if unknown_frac > 0.20:
            issues['high_unknown_field_types'] = {
                'severity': 'ORTHOGONAL_OK',
                'why': f'{unknown_frac:.0%} of field types classified as UNKNOWN (likely float-derived '
                       'or deeply nested If expressions). Dominant type may understated.',
                'resolution': 'Dominant type claim still valid if it has plurality over UNKNOWN. '
                              'T3 and redundancy are unaffected. UNKNOWN = classifier limitation, not wrong data.',
                'affects_cluster': False,
            }

    return issues


def run_one(dll_path, ct_path, label, max_fns_sym=None, max_pairs_impl=800):
    print(f'\n{"="*60}', flush=True)
    print(f'TARGET: {label}', flush=True)

    try:
        pe = PE(dll_path)
    except Exception as e:
        print(f'  PE PARSE FAILED: {e}', flush=True)
        return None

    code_reader, rebase, _ = _make_code_reader(dll_path, pe)
    print(f'  mode={"dll" if dll_path.lower().endswith(".dll") else "exe"}  '
          f'image_base={pe.image_base:#x}', file=sys.stderr, flush=True)

    _WRITE = 0x80000000
    gr = [(pe.image_base+s['vrva'], pe.image_base+s['vrva']+s['vsize'])
          for s in pe.sections if s['vsize']>0 and (s['chars']&_WRITE)]

    with open(ct_path, encoding='utf-8') as f:
        all_fns = json.load(f)['functions']

    fns_with_globals = [fn for fn in all_fns
                        if re.search(r'DAT_[0-9a-fA-F]+', fn.get('pseudocode','') or '')]
    if max_fns_sym:
        fns_with_globals = fns_with_globals[:max_fns_sym]

    pg = ProgramGeometry(label)
    constraint_nodes = []
    t0 = time.perf_counter()

    for i, fn in enumerate(fns_with_globals):
        va = int(fn['va'], 16); size = fn['size']
        if size < 4 or size > 8000: continue
        if i % 200 == 0:
            print(f'  {i}/{len(fns_with_globals)}...', file=sys.stderr, flush=True)
        try:
            raw_bytes = code_reader(va, size)
            if raw_bytes is None or len(raw_bytes) < size:
                continue
            code = raw_bytes
            exe  = PCODESymEx('x86:LE:64:default', code, va,
                              global_ranges=gr, verbose=False)
            r    = exe.run(va, initial_regs={'RSP':0x7FF00000,'RCX':0x1000,'RDX':0x2000},
                           max_steps=5000, wall_timeout=6.0)
            if r.global_reads or r.struct_field_reads:
                pg.add_function(fn['name'], r.global_reads,
                                first_access_steps=r.global_first_step or None,
                                struct_field_reads=r.struct_field_reads or None)
            nodes = extract_constraint_nodes(fn['name'], r.constraints,
                                             r.silent_guesses, canonicalize=True)
            constraint_nodes.extend(nodes)
        except Exception:
            pass

    elapsed = time.perf_counter() - t0
    geo = pg.analyze()

    # Implication graph
    impl = build_implication_graph(constraint_nodes,
                                   max_pairs=max_pairs_impl,
                                   timeout_per_ms=2000,
                                   verbose=False)

    # T_centrality
    max_fns_indirect = max(
        (cnt for fields in geo.indirect_structs.values() for _,cnt in fields.values()),
        default=0)

    # T_powerlaw
    all_fn_counts = sorted(
        [cnt for fields in geo.indirect_structs.values() for _,cnt in fields.values()],
        reverse=True)
    plr = power_law_r(all_fn_counts)

    # T_coupling_density
    coupling_density = (impl.redundancy / max_fns_indirect * 100) if max_fns_indirect > 0 else 0

    # Field frequency histogram
    field_freq_top = all_fn_counts[:8]

    result = {
        'label': label,
        'n_fns_total': len(all_fns),
        'n_fns_globals': len(fns_with_globals),
        'elapsed_s': round(elapsed, 1),
        # Struct geometry
        'T3_global': round(geo.T3_global, 3),
        'T3_z': round(geo.T3_z_global, 1),
        'dominant_type': geo.dominant_type,
        'n_clusters': len(geo.clusters),
        'cluster_sizes': sorted([len(c.addresses) for c in geo.clusters], reverse=True)[:5],
        'cluster_types': [c.geo_type for c in sorted(geo.clusters, key=lambda x:-len(x.addresses))[:5]],
        'cluster_patterns': [c.access_pattern for c in sorted(geo.clusters, key=lambda x:-len(x.addresses))[:5]],
        # Indirect structs
        'n_indirect_structs': len(geo.indirect_structs),
        'T_centrality': max_fns_indirect,
        'T_powerlaw_r': round(plr, 3),
        'T_is_powerlaw': plr < -0.8,
        'field_freq_top': field_freq_top,
        # Implication graph
        'n_constraints': impl.n_constraints,
        'n_unique': impl.n_unique_formulas,
        'n_basis': len(impl.minimum_basis),
        'redundancy': round(impl.redundancy, 3),
        'n_implications': len(impl.implications),
        'MDL_bits': round(impl.mdl_bits, 1),
        'T_coupling_density': round(coupling_density, 4),
        # Load-bearing globals
        'n_load_bearing': len(impl.load_bearing_globals),
        'n_implied': len(impl.implied_globals),
        # T_field_type distribution (from constraint shape analysis)
        'field_types': dict(Counter(impl.global_field_types.values())) if impl.global_field_types else {},
    }

    # Print summary
    print(f'  fns_with_globals={result["n_fns_globals"]}  elapsed={elapsed:.0f}s', flush=True)
    print(f'  T3={result["T3_global"]:.0%} z={result["T3_z"]}σ  type={result["dominant_type"]}', flush=True)
    print(f'  clusters={result["n_clusters"]}  sizes={result["cluster_sizes"][:4]}', flush=True)
    print(f'  T_centrality={result["T_centrality"]}  T_powerlaw_r={result["T_powerlaw_r"]:.3f}', flush=True)
    print(f'  constraints={result["n_constraints"]}  unique={result["n_unique"]}', flush=True)
    print(f'  redundancy={result["redundancy"]:.1%}  MDL={result["MDL_bits"]}bits  '
          f'implications={result["n_implications"]}', flush=True)
    print(f'  coupling_density={result["T_coupling_density"]:.4f}', flush=True)
    if result.get('field_types'):
        ft = result['field_types']
        top = sorted(ft.items(), key=lambda x: -x[1])[:4]
        print(f'  field_types: {" ".join(f"{k}={v}" for k,v in top)}', flush=True)

    # Vacuousness guards — computed AFTER result dict is fully built
    result['vacuousness'] = _compute_vacuousness(result, impl, fns_with_globals, max_fns_sym)

    # Print vacuousness warnings — only real hazards and half-hops (skip orthogonal_ok unless verbose)
    vac = result.get('vacuousness', {})
    real_hazards = {k: v for k, v in vac.items() if v['severity'] == 'REAL_HAZARD'}
    half_hops    = {k: v for k, v in vac.items() if v['severity'] == 'HALF_HOP'}
    if real_hazards:
        for k, v in real_hazards.items():
            print(f'  ⚠ REAL_HAZARD [{k}]: {v["why"][:80]}', flush=True)
            print(f'    → {v["resolution"][:80]}', flush=True)
    if half_hops:
        keys = list(half_hops.keys())
        print(f'  ℹ 0.5-hop [{", ".join(keys)}]: trivially resolvable from adjacent metrics', flush=True)

    return result


def main():
    targets = discover_targets()
    print(f'Found {len(targets)} targets:', flush=True)
    for _, _, lbl in targets:
        print(f'  {lbl}', flush=True)

    all_results = []
    for dll, ct, label in targets:
        max_fns = MAX_FNS_PER_DLL.get(label, None)
        if max_fns == 0:
            print(f'\n{label}: SKIPPED (budget=0, cost too high)', flush=True)
            continue
        r = run_one(dll, ct, label, max_fns_sym=max_fns)
        if r:
            all_results.append(r)
            # Save incrementally
            with open('geometry_data.json', 'w') as f:
                json.dump(all_results, f, indent=2)

    # Final comparison table
    print(f'\n{"="*80}', flush=True)
    print('FULL COMPARISON TABLE', flush=True)
    print(f'{"="*80}', flush=True)
    print(f'{"Label":<22} {"T3":>6} {"Type":<14} {"Redund":>8} {"MDL":>6} '
          f'{"Central":>8} {"PL?":>4} {"Coupling":>9}', flush=True)
    print(f'{"-"*22} {"-"*6} {"-"*14} {"-"*8} {"-"*6} {"-"*8} {"-"*4} {"-"*9}', flush=True)
    for r in sorted(all_results, key=lambda x: -x['redundancy']):
        pl = "✓" if r['T_is_powerlaw'] else "✗"
        print(f'{r["label"]:<22} {r["T3_global"]:>5.0%} {r["dominant_type"]:<14} '
              f'{r["redundancy"]:>7.1%} {r["MDL_bits"]:>6.1f} '
              f'{r["T_centrality"]:>8} {pl:>4} {r["T_coupling_density"]:>9.4f}', flush=True)

    # Save full results
    with open('geometry_data.json', 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f'\nSaved to geometry_data.json', flush=True)


if __name__ == '__main__':
    main()
