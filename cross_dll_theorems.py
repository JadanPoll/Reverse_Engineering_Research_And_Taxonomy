"""
Cross-DLL theorem validation.
Tests T1 (proximity clustering), T2 (co-access density), T3 (alignment), T5 (GCD stride)
across multiple DLLs to check for compiler/ABI invariants.
"""
import json, ctypes, re, sys, time, math, os
from dynamic.pcode_sym import PCODESymEx
from dynamic.execute import DLLExecutor
from pe_utils import PE
from collections import defaultdict, Counter

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

def gcd(a, b):
    while b: a, b = b, a % b
    return a

def gcd_list(lst):
    g = lst[0]
    for x in lst[1:]: g = gcd(g, x)
    return g

def analyze_dll(dll_path, ct_path, label, max_fns=None):
    print(f'\n{"="*60}')
    print(f'TARGET: {label}')

    try:
        pe = PE(dll_path)
        ex = DLLExecutor(dll_path)
    except Exception as e:
        print(f'  LOAD FAILED: {e}'); return None

    rebase = ex.load_base - pe.image_base
    _WRITE = 0x80000000
    gr = [(pe.image_base+s['vrva'], pe.image_base+s['vrva']+s['vsize'])
          for s in pe.sections if s['vsize'] > 0 and (s['chars'] & _WRITE)]

    with open(ct_path) as f:
        all_fns = json.load(f)['functions']

    fns = [fn for fn in all_fns
           if re.search(r'DAT_[0-9a-fA-F]+', fn.get('pseudocode', '') or '')]
    if max_fns:
        fns = fns[:max_fns]

    fn_globals = {}
    t0 = time.perf_counter()
    for i, fn in enumerate(fns):
        va = int(fn['va'], 16)
        size = fn['size']
        if size < 4 or size > 8000:
            continue
        if i % 100 == 0:
            print(f'  {i}/{len(fns)}...', file=sys.stderr, flush=True)
        try:
            code = bytes((ctypes.c_uint8 * size).from_address(va + rebase))
            exe = PCODESymEx('x86:LE:64:default', code, va,
                             global_ranges=gr, verbose=False)
            r = exe.run(va, initial_regs={'RSP': 0x7FF00000, 'RCX': 0x1000},
                        max_steps=5000, wall_timeout=6.0)
            if r.global_reads:
                fn_globals[fn['name']] = frozenset(r.global_reads.keys())
        except Exception:
            pass

    elapsed = time.perf_counter() - t0
    all_globals = sorted(set(g for addrs in fn_globals.values() for g in addrs))
    print(f'  {len(fn_globals)} fns / {len(all_globals)} unique globals ({elapsed:.0f}s)')

    if len(all_globals) < 3:
        print('  Too few globals'); return None

    # T1: proximity clustering (4KB gap)
    GAP = 0x1000
    clusters, cur = [], [all_globals[0]]
    for a in all_globals[1:]:
        if a - cur[-1] <= GAP:
            cur.append(a)
        else:
            clusters.append(cur); cur = [a]
    clusters.append(cur)

    # T3: alignment
    all_offsets = []
    for c in clusters:
        base = min(c)
        for a in c:
            if a != base:
                all_offsets.append(a - base)

    if all_offsets:
        n = len(all_offsets)
        aligned4 = sum(1 for o in all_offsets if o % 4 == 0)
        aligned8 = sum(1 for o in all_offsets if o % 8 == 0)
        t3 = aligned4 / n
        z3 = (aligned4 - 0.25*n) / math.sqrt(n * 0.25 * 0.75) if n > 0 else 0
    else:
        t3, z3, n, aligned4, aligned8 = None, 0, 0, 0, 0

    # T2: co-access density
    coaccesses = defaultdict(int)
    for addrs in fn_globals.values():
        addr_list = sorted(addrs)
        for i, a in enumerate(addr_list):
            for b in addr_list[i+1:]:
                coaccesses[(min(a, b), max(a, b))] += 1

    cluster_densities = []
    for c in clusters:
        if len(c) < 2:
            continue
        pairs = [(min(a, b), max(a, b)) for j, a in enumerate(c) for b in c[j+1:]]
        co = sum(1 for p in pairs if coaccesses[p] > 0)
        cluster_densities.append((len(c), co / len(pairs) if pairs else 0))

    # T5: GCD stride
    stride_findings = []
    for c in clusters:
        if len(c) < 4:
            continue
        sorted_c = sorted(c)
        diffs = [sorted_c[i+1] - sorted_c[i] for i in range(len(sorted_c)-1)]
        if not diffs:
            continue
        g = gcd_list(diffs)
        if g <= 0:
            continue
        multiples = sum(1 for d in diffs if d % g == 0)
        consistency = multiples / len(diffs)
        if consistency >= 0.75 and g > 0:
            n_elements = (max(c) - min(c)) // g + 1
            stride_findings.append({
                'base': min(c), 'span': max(c)-min(c),
                'cluster_size': len(c), 'gcd_stride': g,
                'n_elements': n_elements, 'consistency': consistency,
            })

    # Print results
    print(f'\n  T1 (proximity clusters): {len(clusters)} candidates')
    print(f'    Largest: {sorted([len(c) for c in clusters], reverse=True)[:6]}')

    if t3 is not None:
        print(f'  T3 (4B alignment): {t3:.0%} ({aligned4}/{n})  z={z3:.1f}σ')
        print(f'  T3 (8B alignment): {aligned8/n:.0%} ({aligned8}/{n})')

    print(f'  T2 (co-access densities by cluster size):')
    for size, density in sorted(cluster_densities, key=lambda x: -x[0])[:6]:
        pattern = ('ARRAY' if density < 0.20 else
                   'MONOLITHIC' if density > 0.50 else 'MIXED')
        print(f'    {size:4d} globals: {density:.0%} -> {pattern}')

    if stride_findings:
        print(f'  T5 (GCD stride arrays):')
        for sf in sorted(stride_findings, key=lambda x: -x['cluster_size'])[:4]:
            print(f'    base={sf["base"]:#x} stride=0x{sf["gcd_stride"]:x} '
                  f'x {sf["n_elements"]} elements '
                  f'(size={sf["cluster_size"]} fields, consist={sf["consistency"]:.0%})')
    else:
        print(f'  T5: no clear array structures detected')

    return {
        'label': label,
        'n_globals': len(all_globals),
        'n_clusters': len(clusters),
        'T3': t3,
        'T3_z': z3,
        'T3_n': n,
        'cluster_densities': sorted(cluster_densities, key=lambda x: -x[0]),
        'stride_findings': stride_findings,
    }

DLLS = [
    ('TESTS/real_world/emulators/mgba/mgba_libretro.dll',
     'TESTS/real_world/emulators/mgba/calltree.json',
     'mGBA (game emulator)'),
    ('TESTS/real_world/windows/vcruntime140/vcruntime140.dll',
     'TESTS/real_world/windows/vcruntime140/calltree.json',
     'vcruntime140 (CRT)'),
    ('TESTS/real_world/windows/dxgi/dxgi.dll',
     'TESTS/real_world/windows/dxgi/calltree.json',
     'dxgi (GPU driver)'),
    ('TESTS/real_world/windows/winhttp/winhttp.dll',
     'TESTS/real_world/windows/winhttp/calltree.json',
     'winhttp (TLS/HTTP)'),
    ('TESTS/real_world/windows/kernel32/kernel32.dll',
     'TESTS/real_world/windows/kernel32/calltree.json',
     'kernel32 (Win32 API)'),
]

all_results = []
for dll, ct, label in DLLS:
    try:
        r = analyze_dll(dll, ct, label)
        if r:
            all_results.append(r)
    except Exception as e:
        print(f'{label}: FAILED {e}')

# Cross-DLL summary
print(f'\n{"="*65}')
print('CROSS-DLL INVARIANT SUMMARY')
print(f'{"="*65}')
print(f'  {"DLL":<28} {"Clusters":>8} {"T3 align":>10} {"z-score":>9}')
print(f'  {"-"*28} {"-"*8} {"-"*10} {"-"*9}')

t3_values = []
for r in all_results:
    t3 = r.get('T3')
    z  = r.get('T3_z', 0)
    if t3 is not None:
        t3_values.append(t3)
        print(f'  {r["label"]:<28} {r["n_clusters"]:>8} {t3:>9.0%} {z:>9.1f}s')
    else:
        print(f'  {r["label"]:<28} {r["n_clusters"]:>8} {"N/A":>10} {"":>9}')

if t3_values:
    spread = max(t3_values) - min(t3_values)
    print(f'\n  T3 range: [{min(t3_values):.0%}, {max(t3_values):.0%}]  spread={spread:.0%}')
    if spread < 0.10:
        print('  ** T3 IS A UNIVERSAL INVARIANT (spread < 10%) **')
    else:
        print(f'  T3 varies: NOT a simple universal invariant')

print('\n  T2 pattern summary (ARRAY vs MONOLITHIC):')
for r in all_results:
    densities = [d for _, d in r.get('cluster_densities', [])]
    if not densities:
        continue
    arrays = sum(1 for d in densities if d < 0.20)
    monolithic = sum(1 for d in densities if d > 0.50)
    print(f'  {r["label"]:<28}: {arrays} ARRAY, {monolithic} MONOLITHIC, '
          f'{len(densities)-arrays-monolithic} MIXED clusters')

print('\n  T5 array structures found:')
for r in all_results:
    sf = r.get('stride_findings', [])
    if sf:
        strides_str = ', '.join('0x%x' % s['gcd_stride'] for s in sf[:3])
        print(f'  {r["label"]:<28}: {len(sf)} array(s) — strides: {strides_str}')
    else:
        print(f'  {r["label"]:<28}: none detected')

print('\nDONE')
