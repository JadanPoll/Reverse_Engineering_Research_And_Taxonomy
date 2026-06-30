"""Test T_semantic_cardinality across ZIPF+INDEP vs ZIPF+COUPLED DLLs."""
import json, ctypes, re, sys, math
from dynamic.pcode_sym import PCODESymEx
from dynamic.execute import DLLExecutor
from pe_utils import PE
from dynamic.implication_graph import extract_constraint_nodes
from collections import defaultdict, Counter

sys.stdout.reconfigure(line_buffering=True)

def classify_constant(value, image_base, image_size):
    if value == 0:
        return 'NULL'
    if image_base <= value < image_base + image_size:
        return 'DLL_POINTER'
    if 0x10000 < value < 0xFFFF0000_00000000 and value > 0x10000000:
        return 'HEAP_OR_OS_POINTER'
    if 0xFFFF0000_00000000 <= value:
        return 'SIGNED_NEGATIVE_SEMANTIC'
    if value < 0x10000:
        return 'SMALL_INT_SEMANTIC'
    if value < 0x1000000:
        return 'MEDIUM_INT_SEMANTIC'
    return 'LARGE_UNKNOWN'

def semantic_cardinality(dll_path, ct_path, label, max_fns=300):
    pe = PE(dll_path)
    ex = DLLExecutor(dll_path)
    rebase = ex.load_base - pe.image_base
    image_base = pe.image_base
    image_size = max(s['vrva']+s['vsize'] for s in pe.sections) + 0x1000

    _WRITE = 0x80000000
    gr = [(image_base+s['vrva'], image_base+s['vrva']+s['vsize'])
          for s in pe.sections if s['vsize']>0 and (s['chars']&_WRITE)]

    with open(ct_path) as f:
        fns = [fn for fn in json.load(f)['functions']
               if re.search(r'DAT_[0-9a-fA-F]+', fn.get('pseudocode','') or '')][:max_fns]

    all_nodes = []
    for fn in fns:
        va = int(fn['va'],16); sz = fn['size']
        if sz < 4 or sz > 8000: continue
        try:
            code = bytes((ctypes.c_uint8*sz).from_address(va+rebase))
            exe = PCODESymEx('x86:LE:64:default', code, va,
                             global_ranges=gr, verbose=False)
            r = exe.run(va, initial_regs={'RSP':0x7FF00000,'RCX':0x1000},
                        max_steps=5000, wall_timeout=6.0)
            all_nodes.extend(extract_constraint_nodes(fn['name'], r.constraints,
                                                      r.silent_guesses, canonicalize=True))
        except:
            pass

    var_semantic = defaultdict(set)
    var_classes  = defaultdict(Counter)

    for node in all_nodes:
        formula = node.formula
        if formula is None: continue
        try:
            cond = formula.args[0] if (hasattr(formula,'op') and formula.op=='If') else formula
            if not hasattr(cond,'op'): continue
            if cond.op in ('__eq__','__ne__','ULT','ULE','UGT','UGE','SLT','SLE','SGT','SGE'):
                bvs_args = [a for a in cond.args if hasattr(a,'op') and a.op=='BVS']
                bvv_args = [a for a in cond.args if hasattr(a,'op') and a.op=='BVV']
                if len(bvs_args)==1 and len(bvv_args)==1:
                    var = list(bvs_args[0].variables)[0]
                    val = bvv_args[0].args[0]
                    cls = classify_constant(val, image_base, image_size)
                    var_classes[var][cls] += 1
                    if 'SEMANTIC' in cls:
                        var_semantic[var].add(val)
        except:
            pass

    sem_card = {var: len(consts) for var,consts in var_semantic.items()}
    high_sem  = {var:c for var,c in sem_card.items() if c >= 2}
    total_sem = sum(sem_card.values())

    print(f'\n{label}:')
    print(f'  {len(all_nodes)} constraint nodes  |  sem_card>=2 vars: {len(high_sem)}/{len(var_classes)}  |  total_sem={total_sem}')
    top = sorted(sem_card.items(), key=lambda x:-x[1])[:5]
    for var,sc in top:
        sconsts = sorted(var_semantic[var])
        cls_str = dict(var_classes[var])
        print(f'  sem_card={sc}  {var[:38]:38s}  vals={sconsts[:4]}  {cls_str}')

    return total_sem, len(high_sem)

TARGETS = [
    ('TESTS/real_world/windows/ws2_32/ws2_32.dll',
     'TESTS/real_world/windows/ws2_32/calltree.json',   'ws2_32',  'ZIPF+INDEP,  0.0%'),
    ('C:/Windows/System32/esent.dll',
     'TESTS/real_world/windows/esent/calltree.json',    'esent',   'ZIPF+COUPLED, 9.2%'),
    ('TESTS/real_world/emulators/mgba/mgba_libretro.dll',
     'TESTS/real_world/emulators/mgba/calltree.json',   'mgba',    'ZIPF+COUPLED, 7.9%'),
    ('TESTS/real_world/windows/rpcrt4/rpcrt4.dll',
     'TESTS/real_world/windows/rpcrt4/calltree.json',   'rpcrt4',  'CHAIN+COUPLED, 15.9%'),
    ('TESTS/real_world/windows/dxgi/dxgi.dll',
     'TESTS/real_world/windows/dxgi/calltree.json',     'dxgi',    'ZIPF+INDEP,  0.3%'),
    ('TESTS/real_world/windows/advapi32/advapi32.dll',
     'TESTS/real_world/windows/advapi32/calltree.json', 'advapi32','ZIPF+COUPLED, 5.7%'),
]

results = {}
for dll, ct, lbl, quad in TARGETS:
    try:
        tot, high = semantic_cardinality(dll, ct, f'{lbl} ({quad})')
        results[lbl] = (tot, high, quad)
    except Exception as e:
        print(f'{lbl}: FAILED {e}')

print()
print('='*70)
print('PREDICTION TEST: ZIPF+INDEP should have total_sem=0; ZIPF+COUPLED > 0')
print(f'{"DLL":<12} {"Sem_card":>10} {"High_vars":>10}  Quadrant')
print('-'*70)
for lbl,(tot,high,quad) in sorted(results.items(), key=lambda x:-x[1][0]):
    pred_indep   = 'INDEP' in quad and tot == 0
    pred_coupled = 'COUPLED' in quad and tot > 0
    marker = 'CONFIRMED' if (pred_indep or pred_coupled) else 'WRONG'
    print(f'{lbl:<12} {tot:>10} {high:>10}  {quad}  [{marker}]')
