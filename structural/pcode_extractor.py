"""
pcode_extractor.py — Lift all functions across all DLLs to normalized P-Code tokens.

Design:
  - BFS over basic blocks within each function (not just entry path)
  - Level-0 normalization: suppress SSA artifacts, collapse float/overflow/bool/comparison groups
  - Output size encoding: OPCODE_N where N = output size in bytes
  - STORE_N: N = size of value written (inputs[2].size)
  - Control transfer ops (BRANCH/CBRANCH/BRANCHIND/CALL/CALLIND/RETURN): no size suffix
  - Token sequences → pcode_corpus.jsonl (for Sequitur grammar induction)
  - Frequency vectors → pcode_vectors.npz (for HDBSCAN clustering)

Why output size not input size:
  - Output is the causal downstream signal; input sizes are latent in surrounding context
  - LOAD_8 vs LOAD_4 immediately tells you pointer-width vs int32 access
  - Grammar induction recovers input patterns from sequential context naturally
"""
import os, sys, json, time, ctypes, struct
from collections import defaultdict, Counter

import numpy as np
import pypcode
from pypcode import OpCode

sys.stdout.reconfigure(line_buffering=True)

ARCH = 'x86:LE:64:default'  # default; overridden per-file by detect_arch()

# Ghidra/pypcode architecture strings by ELF machine type
_ARCH_MAP = {
    'EM_X86_64': 'x86:LE:64:default',
    'EM_386':    'x86:LE:32:default',
    'EM_RISCV':  'RISCV:LE:32:default',
    'EM_ARM':    'ARM:LE:32:v8',
    'EM_AARCH64':'AARCH64:LE:64:v8A',
    'EM_MIPS':   'MIPS:BE:32:default',
}

def detect_arch(path: str) -> str:
    """Read ELF machine type and return pypcode architecture string."""
    try:
        from elftools.elf.elffile import ELFFile
        with open(path, 'rb') as f:
            machine = ELFFile(f)['e_machine']
        return _ARCH_MAP.get(machine, ARCH)
    except Exception:
        return ARCH
MAX_FNS_PER_DLL = 5000   # cap for large calltrees (python312 is 4GB JSON)
MAX_FN_SIZE     = 8000   # bytes; skip very large functions
MAX_BB_PER_FN   = 200    # BFS depth cap

# ── Level-0 normalization ────────────────────────────────────────────────────

SUPPRESS = {
    'MULTIEQUAL', 'INDIRECT', 'CAST', 'SEGMENTOP', 'CPOOLREF', 'NEW', 'IMARK',
}

REMAP = {
    # Float arithmetic (11 → 1)
    'FLOAT_ADD':   'FLOAT_ARITH', 'FLOAT_SUB':   'FLOAT_ARITH',
    'FLOAT_MULT':  'FLOAT_ARITH', 'FLOAT_DIV':   'FLOAT_ARITH',
    'FLOAT_SQRT':  'FLOAT_ARITH', 'FLOAT_NEG':   'FLOAT_ARITH',
    'FLOAT_ABS':   'FLOAT_ARITH', 'FLOAT_CEIL':  'FLOAT_ARITH',
    'FLOAT_FLOOR': 'FLOAT_ARITH', 'FLOAT_ROUND': 'FLOAT_ARITH',
    # Float comparison (5 → 1)
    'FLOAT_EQUAL':    'FLOAT_CMP', 'FLOAT_NOTEQUAL': 'FLOAT_CMP',
    'FLOAT_LESS':     'FLOAT_CMP', 'FLOAT_LESSEQUAL':'FLOAT_CMP',
    'FLOAT_NAN':      'FLOAT_CMP',
    # Float conversion (3 → 1)
    'FLOAT_INT2FLOAT':    'FLOAT_CAST', 'FLOAT_FLOAT2FLOAT': 'FLOAT_CAST',
    'FLOAT_TRUNC':        'FLOAT_CAST',
    # Overflow carries (3 → 1)
    'INT_CARRY': 'OVERFLOW_CHECK', 'INT_SCARRY': 'OVERFLOW_CHECK',
    'INT_SBORROW': 'OVERFLOW_CHECK',
    # Ordered unsigned comparison (2 → 1)
    'INT_LESS': 'INT_UCMP', 'INT_LESSEQUAL': 'INT_UCMP',
    # Ordered signed comparison (2 → 1)
    'INT_SLESS': 'INT_SCMP', 'INT_SLESSEQUAL': 'INT_SCMP',
    # Division/modulo signed+unsigned (4 → 2)
    'INT_DIV': 'INT_DIVIDE', 'INT_SDIV': 'INT_DIVIDE',
    'INT_REM': 'INT_MODULO', 'INT_SREM': 'INT_MODULO',
    # Boolean ops (4 → 1): all signal "compound conditional"
    'BOOL_AND': 'BOOL_OP', 'BOOL_OR': 'BOOL_OP',
    'BOOL_XOR': 'BOOL_OP', 'BOOL_NEGATE': 'BOOL_OP',
}

# These produce no output value — no size suffix
NO_SIZE_OPS = {
    'BRANCH', 'CBRANCH', 'BRANCHIND',
    'CALL', 'CALLIND', 'CALLOTHER', 'RETURN',
    'STORE',   # handled separately (inputs[2].size)
}

def normalize_op(op) -> str | None:
    """Return normalized token string for a P-Code op, or None to suppress."""
    name = op.opcode.name
    if name in SUPPRESS:
        return None
    name = REMAP.get(name, name)

    if name == 'STORE':
        # Size = data being written = inputs[2].size
        try:
            sz = op.inputs[2].size
            return f'STORE_{sz}'
        except (IndexError, AttributeError):
            return 'STORE'

    if name in NO_SIZE_OPS:
        return name

    # All other ops: append output size
    out_size = op.output.size if op.output is not None else 0

    # POPCOUNT_1 is the x86 parity-flag artifact (Ghidra emits it after every
    # ADD/SUB/INC/DEC). Real bit-counting produces POPCOUNT_4 or POPCOUNT_8.
    if name == 'POPCOUNT' and out_size == 1:
        return None

    if out_size > 0:
        return f'{name}_{out_size}'
    return name


# ── Basic-block BFS for complete function P-Code ─────────────────────────────

def _branch_target(op) -> int | None:
    """Extract static branch target VA from BRANCH or CBRANCH op, or None."""
    try:
        # BRANCH:  inputs[0] = destination (const space)
        # CBRANCH: inputs[0] = destination (const space), inputs[1] = condition
        vn = op.inputs[0]
        if vn.space.name == 'const':
            return vn.offset
    except (IndexError, AttributeError):
        pass
    return None

def extract_function_tokens(ctx, code_bytes: bytes, base_va: int) -> list[str]:
    """
    BFS over basic blocks within [base_va, base_va+len(code_bytes)).
    Returns flat list of normalized token strings.
    """
    end_va   = base_va + len(code_bytes)
    visited  = set()
    queue    = [base_va]
    tokens   = []
    bb_count = 0

    while queue and bb_count < MAX_BB_PER_FN:
        va = queue.pop(0)
        if va in visited or va < base_va or va >= end_va:
            continue
        visited.add(va)
        bb_count += 1

        offset = va - base_va
        chunk  = code_bytes[offset:]
        try:
            tx = ctx.translate(chunk, va,
                               flags=pypcode.TRANSLATE_FLAGS_BB_TERMINATING)
        except Exception:
            try:
                tx = ctx.translate(chunk[:32], va)
            except Exception:
                continue

        for op in tx.ops:
            tok = normalize_op(op)
            if tok:
                tokens.append(tok)
            # Queue branch targets within function bounds
            if op.opcode.name in ('BRANCH', 'CBRANCH'):
                t = _branch_target(op)
                if t is not None and base_va <= t < end_va and t not in visited:
                    queue.append(t)

    return tokens


# ── DLL / EXE byte reader ─────────────────────────────────────────────────────

def make_reader(dll_path: str):
    """Return (reader_fn, image_base). reader_fn(va, size) → bytes | None."""
    from pe_utils import PE
    pe = PE(dll_path)

    if dll_path.lower().endswith('.dll'):
        try:
            from dynamic.execute import DLLExecutor
            ex     = DLLExecutor(dll_path)
            rebase = ex.load_base - pe.image_base
            def read_dll(va: int, size: int) -> bytes | None:
                try:
                    return bytes((ctypes.c_uint8 * size).from_address(va + rebase))
                except Exception:
                    return None
            return read_dll, pe.image_base
        except Exception:
            pass

    # Fallback: file-offset read (for EXEs and unloadable DLLs)
    raw = open(dll_path, 'rb').read()
    def read_file(va: int, size: int) -> bytes | None:
        try:
            off = pe.va_to_file_offset(va)
            chunk = raw[off: off + size]
            return chunk if len(chunk) == size else None
        except Exception:
            return None
    return read_file, pe.image_base


def load_calltree(ct_path: str, cap: int = MAX_FNS_PER_DLL) -> list[dict]:
    """Load calltree JSON, capping at `cap` functions. Skips huge files via streaming."""
    fsize = os.path.getsize(ct_path)
    if fsize > 300_000_000:  # >300MB — stream with ijson if available
        try:
            import ijson
            fns = []
            with open(ct_path, 'rb') as f:
                for fn in ijson.items(f, 'functions.item'):
                    fns.append(fn)
                    if len(fns) >= cap:
                        break
            return fns
        except ImportError:
            print(f'  SKIP {ct_path}: {fsize//1e6:.0f}MB, install ijson to handle large calltrees')
            return []
    with open(ct_path, encoding='utf-8') as f:
        data = json.load(f)
    return data.get('functions', [])[:cap]


# ── Per-DLL processing ───────────────────────────────────────────────────────

def process_dll(dll_path: str, ct_path: str, label: str,
                ctx: pypcode.Context) -> list[dict]:
    """Extract P-Code tokens for all functions in one DLL. Returns list of records."""
    t0 = time.perf_counter()
    print(f'\n{"─"*55}')
    print(f'  {label}  ({dll_path})')

    fns = load_calltree(ct_path)
    if not fns:
        print('  SKIP: empty or too large calltree')
        return []

    try:
        reader, image_base = make_reader(dll_path)
    except Exception as e:
        print(f'  SKIP: cannot load DLL — {e}')
        return []

    records = []
    n_ok = n_skip = n_err = 0

    for fn in fns:
        try:
            va   = int(fn['va'], 16)
            size = int(fn.get('size', 0))
        except (KeyError, ValueError):
            n_skip += 1; continue
        if size < 4 or size > MAX_FN_SIZE:
            n_skip += 1; continue

        code = reader(va, size)
        if code is None or len(code) < 4:
            n_skip += 1; continue

        try:
            tokens = extract_function_tokens(ctx, code, va)
        except Exception:
            n_err += 1; continue

        if not tokens:
            n_skip += 1; continue

        records.append({
            'dll':    label,
            'fn':     fn.get('name', f'FUN_{va:x}'),
            'va':     va,
            'size':   size,
            'tokens': tokens,
            'n_ops':  len(tokens),
        })
        n_ok += 1

    elapsed = time.perf_counter() - t0
    print(f'  ok={n_ok}  skip={n_skip}  err={n_err}  ({elapsed:.1f}s)')
    return records


# ── Static library processing (.a archives) ──────────────────────────────────

def process_static_lib(a_path: str, label: str, ctx: pypcode.Context = None) -> list[dict]:
    """Extract P-Code tokens from a static library (.a) — full internal symbols."""
    from ar_reader import extract_functions_from_archive
    arch = detect_arch_from_ar(a_path)
    ctx  = pypcode.Context(arch)
    t0 = time.perf_counter()
    print(f'\n{"─"*55}')
    print(f'  {label}  ({a_path})  [STATIC/{arch}]')

    try:
        fns = extract_functions_from_archive(a_path)
    except Exception as e:
        print(f'  SKIP: {e}')
        return []

    records = []
    n_ok = n_skip = n_err = 0

    for fn in fns[:MAX_FNS_PER_DLL]:
        code = fn.get('bytes')
        va   = fn['va']
        if not code or len(code) < 4:
            n_skip += 1; continue
        try:
            tokens = extract_function_tokens(ctx, code, va)
        except Exception:
            n_err += 1; continue
        if not tokens:
            n_skip += 1; continue
        records.append({
            'dll':    label,
            'fn':     fn['name'].split('::')[-1],
            'va':     va,
            'size':   fn['size'],
            'tokens': tokens,
            'n_ops':  len(tokens),
        })
        n_ok += 1

    elapsed = time.perf_counter() - t0
    print(f'  ok={n_ok}  skip={n_skip}  err={n_err}  ({elapsed:.1f}s)')
    return records


def detect_arch_from_ar(a_path: str) -> str:
    """Peek at first .o member in a static lib to get architecture."""
    import io
    from elftools.elf.elffile import ELFFile
    with open(a_path, 'rb') as f:
        data = f.read()
    pos = 8  # skip !<arch>\n
    while pos < len(data):
        if pos + 60 > len(data): break
        hdr  = data[pos:pos+60]
        size = int(hdr[48:58].strip())
        pos += 60
        member = data[pos:pos+size]
        pos += size + (size % 2)
        if member[:4] == b'\x7fELF':
            try:
                return _ARCH_MAP.get(ELFFile(io.BytesIO(member))['e_machine'], ARCH)
            except Exception:
                pass
    return ARCH


# ── ELF processing (Linux .so files) ─────────────────────────────────────────

def process_elf(so_path: str, label: str, ctx: pypcode.Context = None) -> list[dict]:
    """Extract P-Code tokens from a Linux ELF shared library via symbol table."""
    from elf_reader import extract_functions
    arch = detect_arch(so_path)
    ctx  = pypcode.Context(arch)
    t0 = time.perf_counter()
    print(f'\n{"─"*55}')
    print(f'  {label}  ({so_path})  [ELF/{arch}]')

    try:
        fns = extract_functions(so_path)
    except Exception as e:
        print(f'  SKIP: ELF parse failed — {e}')
        return []

    if not fns:
        print('  SKIP: no function symbols found')
        return []

    records = []
    n_ok = n_skip = n_err = 0

    for fn in fns[:MAX_FNS_PER_DLL]:
        code = fn.get('bytes')
        va   = fn['va']
        if not code or len(code) < 4:
            n_skip += 1; continue
        try:
            tokens = extract_function_tokens(ctx, code, va)
        except Exception:
            n_err += 1; continue
        if not tokens:
            n_skip += 1; continue
        records.append({
            'dll':    label,
            'fn':     fn['name'],
            'va':     va,
            'size':   fn['size'],
            'tokens': tokens,
            'n_ops':  len(tokens),
        })
        n_ok += 1

    elapsed = time.perf_counter() - t0
    print(f'  ok={n_ok}  skip={n_skip}  err={n_err}  ({elapsed:.1f}s)')
    return records


# ── Target discovery ─────────────────────────────────────────────────────────

WIN_ROOT = 'TESTS/real_world/windows'
EMU_ROOT = 'TESTS/real_world/emulators'

def discover_targets() -> list[tuple[str, str, str]]:
    """Find all (dll_path, calltree_path, label) pairs."""
    targets = []
    esent_path = 'C:/Windows/System32/esent.dll'
    extra_dlls = {
        'esent':    esent_path,
        'schannel': 'C:/Windows/System32/schannel.dll',
        'py_sqlite': 'C:/Program Files/Python313/DLLs/sqlite3.dll',
    }

    for root in (WIN_ROOT, EMU_ROOT):
        if not os.path.isdir(root):
            continue
        for d in sorted(os.listdir(root)):
            ct = f'{root}/{d}/calltree.json'
            if not os.path.exists(ct):
                continue
            # Find the binary
            dll = extra_dlls.get(d)
            if dll is None:
                for f in os.listdir(f'{root}/{d}'):
                    if f.endswith(('.dll', '.exe')):
                        dll = f'{root}/{d}/{f}'
                        break
            if dll and os.path.exists(dll):
                targets.append((dll, ct, d))

    return targets


ELF_DIR = 'linux_libs'
ELF_LABELS = {
    'libssl.so.3':         'linux_ssl',
    'libsqlite3.so.0':     'linux_sqlite',
    'libpython3.11.so.1.0':'linux_python',
    'libc.so.6':           'linux_libc',
    # Codecs: use static libs (.a) for full internal symbols
    # The .so files only have public API (~50 fns); .a has all internals (~1700 fns)
}

STATIC_LABELS = {
    'libx264.a':  'linux_x264',   # H.264 — motion estimation, DCT, CABAC, deblocking
    'libopus.a':  'linux_opus',   # Opus — CELT Hadamard, SILK LPC, stereo coding
}

def discover_elf_targets() -> list[tuple[str, str]]:
    """Find (so_path, label) for Linux .so files in linux_libs/."""
    targets = []
    if not os.path.isdir(ELF_DIR):
        return targets
    for fname, label in ELF_LABELS.items():
        path = os.path.join(ELF_DIR, fname)
        if os.path.exists(path):
            targets.append((path, label))
    return targets


def discover_static_targets() -> list[tuple[str, str]]:
    """Find (a_path, label) for static libraries (.a) in linux_libs/."""
    targets = []
    if not os.path.isdir(ELF_DIR):
        return targets
    for fname, label in STATIC_LABELS.items():
        path = os.path.join(ELF_DIR, fname)
        if os.path.exists(path):
            targets.append((path, label))
    return targets


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    targets     = discover_targets()
    elf_targets    = discover_elf_targets()
    static_targets = discover_static_targets()
    print(f'Found {len(targets)} PE + {len(elf_targets)} ELF + {len(static_targets)} static targets:')
    for _, _, lbl in targets:
        print(f'  [PE]  {lbl}')
    for _, lbl in elf_targets:
        print(f'  [ELF] {lbl}')

    ctx = pypcode.Context(ARCH)
    all_records: list[dict] = []

    for dll, ct, label in targets:
        recs = process_dll(dll, ct, label, ctx)
        all_records.extend(recs)

    for so_path, label in elf_targets:
        recs = process_elf(so_path, label)
        all_records.extend(recs)

    for a_path, label in static_targets:
        recs = process_static_lib(a_path, label)
        all_records.extend(recs)

    print(f'\n{"="*55}')
    print(f'Total functions extracted: {len(all_records)}')

    # ── Write token sequences (for Sequitur) ────────────────────────────────
    corpus_path = 'pcode_corpus.jsonl'
    with open(corpus_path, 'w', encoding='utf-8') as f:
        for rec in all_records:
            f.write(json.dumps(rec) + '\n')
    print(f'Token sequences → {corpus_path}')

    # ── Build vocabulary + frequency matrix (for clustering) ────────────────
    vocab_counter: Counter = Counter()
    for rec in all_records:
        vocab_counter.update(rec['tokens'])

    vocab = sorted(vocab_counter.keys())
    vocab_index = {t: i for i, t in enumerate(vocab)}
    V = len(vocab)
    N = len(all_records)

    print(f'Vocabulary size: {V} token types')
    print(f'Top 20 tokens:')
    for tok, cnt in vocab_counter.most_common(20):
        print(f'  {tok:<30} {cnt:>10,}')

    # Frequency matrix (float32 to save memory)
    matrix = np.zeros((N, V), dtype=np.float32)
    labels = []
    fn_names = []
    for i, rec in enumerate(all_records):
        for tok in rec['tokens']:
            matrix[i, vocab_index[tok]] += 1
        labels.append(rec['dll'])
        fn_names.append(f"{rec['dll']}::{rec['fn']}")

    # L1-normalize each row (frequency → relative frequency)
    row_sums = matrix.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1
    matrix_norm = matrix / row_sums

    np.savez_compressed('pcode_vectors.npz',
                        matrix=matrix,
                        matrix_norm=matrix_norm,
                        vocab=np.array(vocab),
                        labels=np.array(labels),
                        fn_names=np.array(fn_names))
    print(f'Frequency vectors → pcode_vectors.npz  shape={matrix.shape}')

    # ── Per-DLL summary ──────────────────────────────────────────────────────
    dll_counts = Counter(labels)
    print(f'\nPer-DLL function counts:')
    for lbl, cnt in sorted(dll_counts.items(), key=lambda x: -x[1]):
        print(f'  {lbl:<25} {cnt:>6,}')

    # ── Token diversity per DLL ───────────────────────────────────────────────
    print(f'\nToken diversity (unique tokens / total tokens) per DLL:')
    dll_vocabs: dict[str, Counter] = defaultdict(Counter)
    for rec in all_records:
        dll_vocabs[rec['dll']].update(rec['tokens'])
    for lbl in sorted(dll_vocabs):
        c = dll_vocabs[lbl]
        total = sum(c.values())
        uniq  = len(c)
        print(f'  {lbl:<25} unique={uniq:>4}  total={total:>9,}  entropy={_entropy(c):.2f} bits')

    print('\nDone. Next: pip install scikit-sequitur && python pcode_grammar.py')


def _entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total == 0: return 0.0
    return -sum((c/total) * np.log2(c/total) for c in counter.values() if c > 0)


if __name__ == '__main__':
    main()
