"""
pcode_wl.py — Weisfeiler-Lehman graph kernel on the function call graph.

Each function is currently described by its own P-Code cluster (depth-0).
WL extends this by incorporating call-graph neighborhood context:

  WL-0(f) = cluster_label(f)                                      [what the fn IS]
  WL-1(f) = hash(WL-0(f), sorted(WL-0(callee) for callee in f))  [what it CALLS]
  WL-2(f) = hash(WL-1(f), sorted(WL-1(callee) for callee in f))  [design pattern]
  WL-3(f) = hash(WL-2(f), sorted(WL-2(callee) for callee in f))  [module role]

Key insight: functions with NO resolvable call edges (vtable dispatch, computed
jumps, function pointers) appear as isolated nodes. Their WL-1 label equals their
WL-0 label — no callee context. This is a feature not a flaw: statically opaque
functions form their own WL classes and are highest-priority for LLM exploration.
"""
import json, hashlib, os, sys
from collections import Counter, defaultdict

sys.stdout.reconfigure(line_buffering=True)

MAX_DEPTH    = 3
EXTERNAL_LBL = 'EXTERNAL'   # label for imported functions (outside our corpus)
UNKNOWN_LBL  = 'UNKNOWN'    # label for functions not extracted by pcode_extractor
ISOLATED_LBL = '__ISOLATED__'

# ── Load cluster assignments ───────────────────────────────────────────────────

print('Loading cluster assignments...')
with open('pcode_clusters.json') as f:
    cl_data = json.load(f)

# Map "dll::fn_name" → cluster_id and cluster_label
fn_to_cluster   = {}   # "dll::fn_name" → int cluster_id
fn_to_label_str = {}   # "dll::fn_name" → label string
cluster_labels  = cl_data['cluster_labels']   # {"0": "CALLER", ...}

for fn_name, dll, cid in zip(cl_data['fn_names'], cl_data['dll'], cl_data['cluster']):
    fn_to_cluster[fn_name] = cid
    fn_to_label_str[fn_name] = cluster_labels.get(str(cid), 'NOISE' if cid == -1 else f'C{cid}')

print(f'  {len(fn_to_cluster):,} functions with cluster assignments')

# ── Build per-DLL VA → fn_key mappings ────────────────────────────────────────
# "fn_key" = "dll::fn_name", matching pcode_clusters.json

CALLTREE_ROOTS = [
    ('TESTS/real_world/windows/advapi32',    'advapi32'),
    ('TESTS/real_world/windows/combase',     'combase'),
    ('TESTS/real_world/windows/crypt32',     'crypt32'),
    ('TESTS/real_world/windows/dxgi',        'dxgi'),
    ('TESTS/real_world/windows/esent',       'esent'),
    ('TESTS/real_world/windows/kernel32',    'kernel32'),
    ('TESTS/real_world/windows/kernelbase',  'kernelbase'),
    ('TESTS/real_world/windows/ntdll',       'ntdll'),
    ('TESTS/real_world/windows/rpcrt4',      'rpcrt4'),
    ('TESTS/real_world/windows/schannel',    'schannel'),
    ('TESTS/real_world/windows/vcruntime140','vcruntime140'),
    ('TESTS/real_world/windows/winhttp',     'winhttp'),
    ('TESTS/real_world/windows/ws2_32',      'ws2_32'),
    ('TESTS/real_world/emulators/mgba',      'mgba'),
    ('TESTS/real_world/emulators/python312', 'python312'),
    ('TESTS/real_world/emulators/qemu_avr',  'qemu_avr'),
    ('TESTS/real_world/emulators/qemu_i386', 'qemu_i386'),
]

print('\nBuilding call graphs...')
va_to_fnkey   = {}    # int(va) → "dll::fn_name"  (for all DLLs)
fn_callees    = {}    # "dll::fn_name" → list of "dll::fn_name" or EXTERNAL
fn_callers    = {}    # "dll::fn_name" → list of "dll::fn_name"
fn_to_dll     = {}    # "dll::fn_name" → dll string

total_edges = 0

for root, dll in CALLTREE_ROOTS:
    ct_path = f'{root}/calltree.json'
    if not os.path.exists(ct_path):
        continue

    sz = os.path.getsize(ct_path)
    if sz > 300_000_000:
        try:
            import ijson
            fns = []
            with open(ct_path, 'rb') as f:
                for fn in ijson.items(f, 'functions.item'):
                    fns.append(fn)
        except ImportError:
            print(f'  SKIP {dll}: large calltree, install ijson')
            continue
    else:
        with open(ct_path, encoding='utf-8', errors='replace') as f:
            fns = json.load(f)['functions']

    # First pass: register all VA → fnkey mappings for this DLL
    dll_va_map = {}
    for fn in fns:
        try:
            va  = int(fn['va'], 16)
            key = f"{dll}::{fn['name']}"
            dll_va_map[va] = key
            va_to_fnkey[va] = key   # global map (last writer wins for cross-DLL)
            fn_to_dll[key]  = dll
        except (KeyError, ValueError):
            continue

    # Second pass: build call edges
    for fn in fns:
        try:
            va      = int(fn['va'], 16)
            fn_key  = dll_va_map.get(va)
            if fn_key is None:
                continue

            called  = fn.get('called_vas') or []
            callees = []
            for cva in called:
                try:
                    cva_int = int(cva, 16) if isinstance(cva, str) else int(cva)
                except (ValueError, TypeError):
                    continue
                # Resolve callee: prefer same-DLL, then global, then EXTERNAL
                callee_key = dll_va_map.get(cva_int) or va_to_fnkey.get(cva_int)
                if callee_key is None:
                    callee_key = EXTERNAL_LBL
                callees.append(callee_key)

            fn_callees[fn_key] = callees
            total_edges += len([c for c in callees if c != EXTERNAL_LBL])

            for callee_key in callees:
                if callee_key != EXTERNAL_LBL:
                    fn_callers.setdefault(callee_key, []).append(fn_key)
        except (KeyError, ValueError):
            continue

    print(f'  {dll}: {len(dll_va_map):,} fns loaded')

all_fn_keys = set(fn_to_cluster.keys()) | set(fn_callees.keys())
print(f'\n  Total functions in call graph: {len(all_fn_keys):,}')
print(f'  Total call edges (intra-corpus): {total_edges:,}')
isolated = sum(1 for k in fn_to_cluster if not fn_callees.get(k))
print(f'  Isolated nodes (no resolvable callees): {isolated:,}  '
      f'({isolated/len(fn_to_cluster)*100:.1f}%)')
print(f'  → These are highest-priority for LLM exploration (opaque to static analysis)')

# ── WL kernel computation ──────────────────────────────────────────────────────

def _stable_hash(s: str) -> int:
    """Stable 32-bit hash (not Python's built-in which changes per-session)."""
    return int(hashlib.md5(s.encode()).hexdigest()[:8], 16)

def wl_label(fn_key: str, depth_labels: dict[str, str]) -> str:
    """Compute next-depth WL label for fn_key given current depth labels."""
    own = depth_labels.get(fn_key, UNKNOWN_LBL)
    callee_keys = fn_callees.get(fn_key, [])
    callee_labels = sorted(
        depth_labels.get(ck, EXTERNAL_LBL) for ck in callee_keys
    )
    return f'{own}|{",".join(callee_labels)}'

print('\nComputing WL labels...')

# WL-0: just the cluster label string
wl = {}   # fn_key → list of labels at each depth [wl0, wl1, wl2, wl3]
for fn_key in all_fn_keys:
    wl[fn_key] = [fn_to_label_str.get(fn_key, UNKNOWN_LBL)]

# WL-1 through WL-MAX_DEPTH
for depth in range(1, MAX_DEPTH + 1):
    prev_labels = {k: v[depth-1] for k, v in wl.items()}
    new_labels  = {k: wl_label(k, prev_labels) for k in wl}
    # Compress: map full strings to shorter canonical IDs
    unique = sorted(set(new_labels.values()))
    compress = {s: f'L{depth}_{i}' for i, s in enumerate(unique)}
    for k in wl:
        wl[k].append(compress[new_labels[k]])
    print(f'  WL-{depth}: {len(unique):,} unique labels  '
          f'(from {len(set(v[depth-1] for v in wl.values())):,} at depth-{depth-1})')

# ── Analysis ───────────────────────────────────────────────────────────────────

print(f'\n{"="*70}')
print('WL LABEL DISTRIBUTION ACROSS DEPTHS')
print(f'{"="*70}')

for depth in range(MAX_DEPTH + 1):
    labels_at_d = Counter(v[depth] for k, v in wl.items()
                          if k in fn_to_cluster)
    n_unique = len(labels_at_d)
    top5 = labels_at_d.most_common(5)
    # Decode WL-0 labels (they're already strings)
    print(f'\nWL-{depth}: {n_unique:,} unique labels')
    print(f'  Top 5 by count:')
    for lbl, cnt in top5:
        if depth == 0:
            print(f'    {lbl:<20} {cnt:>6,}')
        else:
            # Find what cluster-labels make up this WL label
            members = [k for k, v in wl.items() if v[depth] == lbl and k in fn_to_cluster]
            dll_dist = Counter(fn_to_dll.get(k,'?') for k in members)
            dl_str = ', '.join(f'{d}({n})' for d,n in dll_dist.most_common(3))
            # Show base cluster breakdown
            base = Counter(wl[k][0] for k in members)
            base_str = ', '.join(f'{b}:{n}' for b,n in base.most_common(3))
            print(f'    {lbl:<12} ×{cnt:>5,}  base=[{base_str}]  dlls=[{dl_str}]')

# ── Design pattern discovery at WL-2 ──────────────────────────────────────────

def _name_pattern(own: str, callee_dist: list, dll_dist: Counter) -> str:
    callee_labels = [c for c, _ in callee_dist]
    callee_str = ' '.join(callee_labels).upper()
    if 'GUARD' in own.upper() and not callee_labels:
        return 'PURE_GUARD'
    if 'GETTER' in own.upper() and not callee_labels:
        return 'LEAF_GETTER'
    if 'READER' in own.upper() and 'GUARD' in callee_str:
        return 'GUARDED_READER'
    if 'WRITER' in own.upper() and 'READER' in callee_str:
        return 'READ_THEN_WRITE'
    if 'CALLER' in own.upper() and 'GUARD' in callee_str:
        return 'GUARD_THEN_CALL'
    if 'CALLER' in own.upper() and not callee_labels:
        return 'ISOLATED_CALLER'
    if not callee_labels:
        return f'LEAF_{own.upper()[:8]}'
    if len(callee_dist) == 1 and callee_dist[0][1] > 0.8 * sum(n for _,n in callee_dist):
        return f'{own.upper()[:6]}→{callee_labels[0].upper()[:6]}'
    return f'{own.upper()[:8]}_MIXED'

print(f'\n{"="*70}')
print('DESIGN PATTERNS AT WL-2 (groups with ≥100 members)')
print(f'{"="*70}')

wl2_groups = defaultdict(list)
for fn_key in fn_to_cluster:
    if len(wl[fn_key]) > 2:
        wl2_groups[wl[fn_key][2]].append(fn_key)

# Filter to groups with ≥100 members and analyze
patterns = [(len(members), lbl, members)
            for lbl, members in wl2_groups.items()
            if len(members) >= 100]
patterns.sort(reverse=True)

print(f'  Groups with ≥100 members: {len(patterns)}')

for cnt, lbl, members in patterns[:30]:
    dll_dist  = Counter(fn_to_dll.get(k,'?') for k in members)
    base_dist = Counter(wl[k][0] for k in members)
    d1_dist   = Counter(wl[k][1] for k in members)

    # What does this function call? (from WL-1 decoding)
    callee_base_labels = []
    for fn_key in members[:200]:
        for ck in fn_callees.get(fn_key, []):
            if ck != EXTERNAL_LBL:
                callee_base_labels.append(wl.get(ck, [UNKNOWN_LBL])[0])
    callee_dist = Counter(callee_base_labels).most_common(4)

    own_label   = base_dist.most_common(1)[0][0] if base_dist else '?'
    callee_str  = ', '.join(f'{c}({n})' for c,n in callee_dist)
    dll_str     = ', '.join(f'{d}({n})' for d,n in dll_dist.most_common(3))

    # Attempt to name the design pattern
    pattern_name = _name_pattern(own_label, callee_dist, dll_dist)

    print(f'\n[{pattern_name}] n={cnt:,}')
    print(f'  Self:    {own_label}')
    print(f'  Calls:   {callee_str}')
    print(f'  DLLs:    {dll_str}')

def _name_pattern_unused(own: str, callee_dist: list, dll_dist: Counter) -> str:
    callee_labels = [c for c, _ in callee_dist]
    callee_str = ' '.join(callee_labels).upper()
    if 'GUARD' in own.upper() and not callee_labels:
        return 'PURE_GUARD'
    if 'GETTER' in own.upper() and not callee_labels:
        return 'LEAF_GETTER'
    if 'READER' in own.upper() and 'GUARD' in callee_str:
        return 'GUARDED_READER'
    if 'WRITER' in own.upper() and 'READER' in callee_str:
        return 'READ_THEN_WRITE'
    if 'CALLER' in own.upper() and 'GUARD' in callee_str:
        return 'GUARD_THEN_CALL'
    if 'CALLER' in own.upper() and not callee_labels:
        return 'ISOLATED_CALLER'
    if not callee_labels:
        return f'LEAF_{own.upper()[:8]}'
    if len(callee_dist) == 1 and callee_dist[0][1] > 0.8 * sum(n for _,n in callee_dist):
        return f'{own.upper()[:6]}→{callee_labels[0].upper()[:6]}'
    return f'{own.upper()[:8]}_MIXED'

# ── DLL enrichment per WL-2 pattern ───────────────────────────────────────────

print(f'\n{"="*70}')
print('DLL-SPECIFIC WL-2 PATTERNS (enrichment > 3× global rate)')
print(f'{"="*70}')

dll_totals = Counter(fn_to_dll.get(k,'?') for k in fn_to_cluster)
global_rate = {dll: n / sum(dll_totals.values()) for dll, n in dll_totals.items()}

for cnt, lbl, members in patterns:
    if cnt < 50:
        continue
    dll_dist = Counter(fn_to_dll.get(k,'?') for k in members)
    for dll, n in dll_dist.most_common(3):
        local_rate  = n / cnt
        global_r    = global_rate.get(dll, 0.001)
        enrichment  = local_rate / global_r if global_r > 0 else 0
        if enrichment > 3.0 and n > 20:
            base_str = Counter(wl[k][0] for k in members).most_common(1)[0][0]
            callee_labels = []
            for fn_key in members[:100]:
                for ck in fn_callees.get(fn_key, []):
                    if ck != EXTERNAL_LBL:
                        callee_labels.append(wl.get(ck, [UNKNOWN_LBL])[0])
            callee_top = Counter(callee_labels).most_common(2)
            callee_str = '→'.join(c for c,_ in callee_top) if callee_top else '(leaf)'
            print(f'  {dll:<15} {enrichment:>4.1f}× enriched  '
                  f'n={n}/{cnt}  [{base_str} {callee_str}]')

# ── Isolated nodes: the LLM exploration priority list ─────────────────────────

print(f'\n{"="*70}')
print('ISOLATED NODES BY DLL (opaque to static analysis → explore first)')
print(f'{"="*70}')

isolated_by_dll = defaultdict(list)
for fn_key in fn_to_cluster:
    if not fn_callees.get(fn_key):
        isolated_by_dll[fn_to_dll.get(fn_key,'?')].append(fn_key)

for dll, fns in sorted(isolated_by_dll.items(), key=lambda x: -len(x[1])):
    total_dll = dll_totals.get(dll, 1)
    pct = len(fns) / total_dll * 100
    base_dist = Counter(wl[k][0] for k in fns).most_common(3)
    base_str  = ', '.join(f'{b}({n})' for b,n in base_dist)
    print(f'  {dll:<20} {len(fns):>5,}/{total_dll:>5,} ({pct:>4.1f}%)  [{base_str}]')

# ── Save ──────────────────────────────────────────────────────────────────────

print('\nSaving WL labels...')
wl_out = {
    fn_key: {
        'wl0': labels[0],
        'wl1': labels[1] if len(labels) > 1 else None,
        'wl2': labels[2] if len(labels) > 2 else None,
        'wl3': labels[3] if len(labels) > 3 else None,
        'dll': fn_to_dll.get(fn_key,'?'),
        'n_callees': len([c for c in fn_callees.get(fn_key,[]) if c != EXTERNAL_LBL]),
        'n_ext_callees': sum(1 for c in fn_callees.get(fn_key,[]) if c == EXTERNAL_LBL),
        'n_callers': len(fn_callers.get(fn_key,[])),
        'isolated': not bool(fn_callees.get(fn_key)),
    }
    for fn_key, labels in wl.items()
    if fn_key in fn_to_cluster
}

with open('pcode_wl.json', 'w') as f:
    json.dump(wl_out, f)

print(f'  Saved {len(wl_out):,} functions → pcode_wl.json')
print(f'\nDone. WL-2 groups correspond to design patterns;')
print(f'isolated nodes are highest-priority for LLM budget allocation.')
