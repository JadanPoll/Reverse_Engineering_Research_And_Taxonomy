"""
dynamic/pcode_sym.py — Minimal P-CODE symbolic executor for global init inference.

Design principles (informed by reading naaz + jevinskie/pypcode-emu source):
  - Concrete-first: values are Python int unless a global LOAD made them symbolic
  - Global LOADs → claripy.BVS — the ONLY source of symbolic values
  - Arithmetic propagates symbolism: int OP BVS → BVS (claripy handles this)
  - CBRANCH on BVS → record constraint, DON'T fork (not a full path explorer)
  - FLOAT_* → log + stub with 0 (our targets don't need float symbolics)
  - CALL/CALLIND/CALLOTHER → stub (RAX=0, skip body)
  - Architecture-independent: pass any pypcode arch string

EMPIRICALLY VERIFIED (do not trust docs/training data — test each before using):
  - ctx.getAllRegisters() → {Varnode: str}  key=varnode, value=name  (REVERSED from expected)
  - ctx.spaces DOES NOT EXIST in pypcode 4.0 (use vn.space.name instead)
  - ctx.get_register_names() DOES NOT EXIST in pypcode 4.0 (use getAllRegisters())
  - res.instructions DOES NOT EXIST (jevinskie's API, removed) — use tx.ops
  - TRANSLATE_FLAGS_BB_TERMINATING=1 exists and works correctly
  - claripy BV.length gives BITS (not bytes) — _bits() must NOT be applied to it
  - claripy pinned z3 to 4.13.0 when installed (despite agent claiming 4.16 safe)
  - kc0bfv/pcode-emulator is a Ghidra Java plugin, NOT standalone Python (agent lied)
  - MOV RAX,[RIP+offset] translates as COPY ram[addr]:8 (not LOAD) in pypcode 4.0

Ground-truthed API (pypcode 4.0.0, empirically verified — NOT from docs):
  ctx = pypcode.Context('x86:LE:64:default')
  tx  = ctx.translate(code_bytes, base_addr)   # → Translation with .ops list
  op.opcode   → pypcode.OpCode enum
  op.inputs   → list[Varnode]
  op.output   → Varnode | None
  vn.space.name → 'register' | 'ram' | 'const' | 'unique'
  vn.offset   → int  (for const space: offset IS the value)
  vn.size     → int  (bytes)
  ctx.getAllRegisters() → {Varnode: str}  (key=varnode, value=name)

Space semantics (verified):
  const    → value = offset (literal immediate)
  register → x86: RAX=0,RCX=8,RDX=0x10,RBX=0x18,RSP=0x20,RIP=0x288
              flags: CF=0x200,ZF=0x206,SF=0x207,OF=0x20b
  unique   → temporaries, reset each instruction
  ram      → code + data; global section reads → BVS stubs

Pitfalls found in reference code:
  - CBRANCH can occur mid-basic-block (not just at end)
  - INT_SBORROW needs sign-extension logic (see naaz's implementation)
  - SUBPIECE: truncate from low byte OR shift then truncate (second input = byte offset)
  - Division by zero: add solver constraint `divisor != 0` before dividing symbolically
  - POPCOUNT: appears in parity flag computation of every INC/DEC/ADD/SUB
"""
from __future__ import annotations
import sys, os, math
from dataclasses import dataclass, field
from typing import Union

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import pypcode
    from pypcode import OpCode
    _HAS_PYPCODE = True
except ImportError:
    _HAS_PYPCODE = False

try:
    import claripy
    _HAS_CLARIPY = True
except ImportError:
    _HAS_CLARIPY = False

# A value is either a concrete Python int or a claripy symbolic BitVec
Val = Union[int, "claripy.ast.Base"]

# Float sign domain — tracks sign of float values without full IEEE 754 symbolics.
# Why: full FP symbolic (claripy.FPS) costs 118-335ms per Z3 call (10-20x bitvector).
# For loop termination (FLOAT_GT(x, 0.0)), sign is sufficient.
# From Abstract Interpretation sign domain (Cousot 1977).
class FSign:
    """Abstract float sign: POSITIVE, NEGATIVE, ZERO, or UNKNOWN."""
    __slots__ = ('sign',)
    def __init__(self, s): self.sign = s  # 'POS', 'NEG', 'ZERO', 'UNK'
    def __repr__(self): return f'FSign({self.sign})'

_FSIGN_POS  = FSign('POS')
_FSIGN_NEG  = FSign('NEG')
_FSIGN_ZERO = FSign('ZERO')
_FSIGN_UNK  = FSign('UNK')

def _fsign(v) -> FSign:
    """Get sign domain value for a concrete int (from int-to-float conversion)."""
    if isinstance(v, FSign): return v
    if not isinstance(v, int): return _FSIGN_UNK
    if v == 0: return _FSIGN_ZERO
    # Treat symbolic ints as unknown sign
    if _is_sym(v): return _FSIGN_UNK
    n = int(v)
    if n > 0: return _FSIGN_POS
    return _FSIGN_NEG

def _fsign_mul(a: FSign, b: FSign) -> FSign:
    if a.sign == 'ZERO' or b.sign == 'ZERO': return _FSIGN_ZERO
    if a.sign == 'UNK' or b.sign == 'UNK': return _FSIGN_UNK
    if a.sign == b.sign: return _FSIGN_POS
    return _FSIGN_NEG

def _fsign_add(a: FSign, b: FSign) -> FSign:
    if a.sign == b.sign: return a
    if 'ZERO' in (a.sign, b.sign): return b if a.sign == 'ZERO' else a
    return _FSIGN_UNK  # POS+NEG unknown without magnitudes

def _fsign_neg(a: FSign) -> FSign:
    if a.sign == 'POS': return _FSIGN_NEG
    if a.sign == 'NEG': return _FSIGN_POS
    return a

def _fsign_gt_zero(a: FSign) -> bool | None:
    """Does a > 0? Returns True/False/None (None = unknown)."""
    if a.sign == 'POS': return True
    if a.sign in ('NEG', 'ZERO'): return False
    return None  # unknown


# ── Helpers ───────────────────────────────────────────────────────────────────

def _bits(size_bytes: int) -> int:
    return size_bytes * 8

def _mask(size_bytes: int) -> int:
    return (1 << _bits(size_bytes)) - 1

def _is_sym(v: Val) -> bool:
    return _HAS_CLARIPY and isinstance(v, claripy.ast.Base)

def _to_bv(v: Val, size_bytes: int) -> "claripy.ast.Base":
    """Coerce v to a claripy BV of exactly size_bytes*8 bits.

    BUG TRAP: if v is already symbolic but wrong width, we MUST resize — NOT
    just return v. Returning wrong-width BV causes ClaripyOperationError on
    the next binary op (wrong sizes must match). Fail loudly here instead.
    """
    target_bits = _bits(size_bytes)
    if _is_sym(v):
        current_bits = v.length  # claripy BV.length is bits (NOT bytes)
        if current_bits == target_bits:
            return v
        elif current_bits > target_bits:
            return claripy.Extract(target_bits - 1, 0, v)
        else:
            return claripy.ZeroExt(target_bits - current_bits, v)
    return claripy.BVV(int(v) & _mask(size_bytes), target_bits)

def _ast_complexity(expr) -> tuple[int, int]:
    """Return (max_depth, total_node_count) of a claripy AST. Bounded to avoid blow-up."""
    if not hasattr(expr, 'args'):
        return 0, 1
    visited = {}
    def _walk(node, depth):
        node_id = id(node)
        if node_id in visited:
            return visited[node_id]
        if depth > 64 or not hasattr(node, 'args') or not node.args:
            visited[node_id] = (depth, 1)
            return depth, 1
        max_d, total = depth, 1
        for child in node.args:
            d, n = _walk(child, depth + 1)
            if d > max_d: max_d = d
            total += n
        visited[node_id] = (max_d, total)
        return max_d, total
    try:
        return _walk(expr, 0)
    except Exception:
        return -1, -1


def _concrete(v: Val, size_bytes: int, solver: "claripy.Solver | None" = None,
              _warn_tag: str = "") -> int:
    """Evaluate a (possibly symbolic) value to a concrete int.
    For symbolic values: uses solver model evaluation if available.
    Returns (value, guessed) — caller must record guess if guessed=True.
    """
    if not _is_sym(v):
        return int(v) & _mask(size_bytes)
    if solver is not None:
        try:
            solutions = solver.eval(v, 1)
            if solutions:
                return int(solutions[0]) & _mask(size_bytes)
        except Exception:
            pass
    # Silent fallback — CALLER must log this
    return 1

def _sext(v: int, from_bytes: int, to_bytes: int) -> int:
    """Sign-extend v from from_bytes to to_bytes (concrete)."""
    sign_bit = 1 << (_bits(from_bytes) - 1)
    v = v & _mask(from_bytes)
    if v & sign_bit:
        v |= _mask(to_bytes) ^ _mask(from_bytes)
    return v & _mask(to_bytes)

def _popcount(v: int) -> int:
    return bin(v).count('1')


# ── Address space state ───────────────────────────────────────────────────────

class SpaceState:
    """
    Byte-addressed value store for one P-CODE address space.
    Values are stored at their (offset, size) key.
    Supports mixing concrete ints and claripy BVs.
    """
    def __init__(self, name: str):
        self.name = name
        self._store: dict[tuple[int,int], Val] = {}

    def read(self, offset: int, size: int) -> Val:
        key = (offset, size)
        if key in self._store:
            return self._store[key]
        # Try sub-register reads (e.g. EAX at same offset as RAX but size=4)
        for (off, sz), val in self._store.items():
            if off == offset and sz > size:
                # Truncate to lower bytes
                if _is_sym(val):
                    return claripy.Extract(_bits(size) - 1, 0, val)
                return int(val) & _mask(size)
        return 0  # default: zero

    def write(self, offset: int, size: int, val: Val) -> None:
        if _is_sym(val):
            self._store[(offset, size)] = val
        else:
            self._store[(offset, size)] = int(val) & _mask(size)
            # Also clear any larger overlapping entry to avoid stale sub-reads
            for key in list(self._store.keys()):
                off, sz = key
                if off == offset and sz > size and not _is_sym(self._store[key]):
                    existing = int(self._store[key])
                    mask_low = _mask(size)
                    new_val = (existing & ~mask_low) | (int(val) & mask_low)
                    self._store[key] = new_val & _mask(sz)

    def reset(self) -> None:
        self._store.clear()


# ── Global constraint accumulator ────────────────────────────────────────────

@dataclass
class GlobalConstraint:
    """One constraint on a global address observed during symbolic execution."""
    addr:       int              # Ghidra VA of the global (ram space address)
    size:       int              # bytes read
    sym_name:   str              # claripy variable name
    constraint: object           # claripy formula (the CBRANCH condition)
    branch_taken: bool           # which branch was concretely followed


@dataclass
class ConstraintTiming:
    """Timing and complexity for one solver.eval() call at a CBRANCH."""
    cbranch_va:    int     # address of the CBRANCH instruction
    eval_ms:       float   # how long solver.eval() took (ms)
    ast_depth:     int     # depth of the condition AST
    ast_nodes:     int     # total nodes in the condition AST
    n_vars:        int     # how many distinct symbolic vars in this condition
    n_solver_cons: int     # number of constraints in solver at time of eval
    timed_out:     bool    # True if solver returned [] (timeout/unsat)
    both_sat:      bool    # True if BOTH branches were satisfiable (ambiguous)


@dataclass
class ExecResult:
    """Result of symbolically executing one function."""
    ok:              bool
    constraints:     list[GlobalConstraint]  = field(default_factory=list)
    global_reads:    dict[int, int]          = field(default_factory=dict)   # {addr: size}
    stub_calls:      list[int]               = field(default_factory=list)   # VAs stubbed
    unimpl_ops:      list[str]               = field(default_factory=list)   # unknown opcodes hit
    float_stubs:     list[str]               = field(default_factory=list)   # float ops stubbed to 0
    silent_guesses:  list[str]               = field(default_factory=list)   # any silent fallback
    error:           str                     = ""
    # ── Telemetry (populated when collect_timing=True) ──────────────────────────
    elapsed_ms:      float                   = 0.0   # total wall time
    steps_taken:     int                     = 0     # P-CODE ops executed
    cbranch_timings: list[ConstraintTiming]  = field(default_factory=list)
    ops_histogram:   dict[str, int]          = field(default_factory=dict)   # opcode → count
    solver_resets:   int                     = 0     # how many times solver was reset
    translate_calls: int                     = 0     # pypcode ctx.translate() calls
    # P8: first-access step for each global (low step = guard/null-check, high = compute)
    global_first_step: dict[int, int]        = field(default_factory=dict)   # {addr: step}
    # Direct vs indirect global access decomposition
    # global_reads = DIRECT reads (addr is literally in .data section)
    # struct_field_reads = INDIRECT reads through a global pointer:
    #   (global_base_addr, field_offset, field_size)
    # This separates "array of global variables" from "struct fields via pointer"
    struct_field_reads: list               = field(default_factory=list)     # [(base, offset, size)]

    @property
    def confidence(self) -> str:
        """LOW if any silent guesses, MEDIUM if float/call stubs only, HIGH otherwise."""
        if self.silent_guesses or self.unimpl_ops:
            return "LOW"
        if self.float_stubs or self.stub_calls:
            return "MEDIUM"
        return "HIGH"

    def timing_summary(self) -> dict:
        """Summarize CBRANCH solver timings — the expensive operations."""
        if not self.cbranch_timings:
            return {}
        times = [t.eval_ms for t in self.cbranch_timings]
        depths = [t.ast_depth for t in self.cbranch_timings]
        nodes = [t.ast_nodes for t in self.cbranch_timings]
        n_cons = [t.n_solver_cons for t in self.cbranch_timings]
        return {
            'n_cbranch_evals':     len(times),
            'total_solver_ms':     sum(times),
            'max_solver_ms':       max(times),
            'p95_solver_ms':       sorted(times)[int(len(times)*0.95)],
            'n_timed_out':         sum(1 for t in self.cbranch_timings if t.timed_out),
            'n_ambiguous':         sum(1 for t in self.cbranch_timings if t.both_sat),
            'max_ast_depth':       max(depths),
            'max_ast_nodes':       max(nodes),
            'max_solver_cons_at_eval': max(n_cons),
            'top_slow_cbranches':  sorted(
                [(t.eval_ms, t.cbranch_va, t.ast_nodes, t.n_solver_cons)
                 for t in self.cbranch_timings], reverse=True
            )[:5],
        }


# ── Core executor ─────────────────────────────────────────────────────────────

class PCODESymEx:
    """
    Minimal P-CODE symbolic executor.

    Usage:
        exe = PCODESymEx('x86:LE:64:default', code_bytes, base_va,
                         global_ranges=[(lo, hi), ...])
        result = exe.run(entry_va, initial_regs={'RCX': 0x1000, 'RSP': 0x7ff00000})
        # result.constraints: which CBRANCHes depended on global reads
        # result.global_reads: which globals were read and their sizes
    """

    MAX_STEPS = 50_000

    def __init__(
        self,
        arch_str:      str,
        code_bytes:    bytes,
        base_va:       int,
        global_ranges: list[tuple[int,int]] | None = None,
        verbose:       bool = False,
    ):
        if not _HAS_PYPCODE:
            raise ImportError("pip install pypcode")
        if not _HAS_CLARIPY:
            raise ImportError("pip install claripy")

        self.ctx       = pypcode.Context(arch_str)
        self.code      = code_bytes
        self.base_va   = base_va
        self.end_va    = base_va + len(code_bytes)
        self.global_ranges = global_ranges or []
        self.verbose   = verbose

        # Build (offset, size) → register_name for debug printing
        self._reg_names: dict[tuple[int,int], str] = {
            (vn.offset, vn.size): name
            for vn, name in self.ctx.getAllRegisters().items()
        }
        # Reverse: name → (offset, size)
        self._reg_offsets: dict[str, tuple[int,int]] = {
            v: k for k, v in self._reg_names.items()
        }

    def _is_global(self, addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in self.global_ranges)

    def _translate(self, va: int) -> list:
        """Translate one basic block starting at va."""
        offset = va - self.base_va
        if offset < 0 or offset >= len(self.code):
            return []
        chunk = self.code[offset:]
        try:
            tx = self.ctx.translate(chunk, va,
                                    flags=pypcode.TRANSLATE_FLAGS_BB_TERMINATING)
            return tx.ops
        except Exception:
            # Fallback: translate without BB termination
            try:
                tx = self.ctx.translate(chunk[:32], va)
                return tx.ops
            except Exception:
                return []

    def _read_vn(self, vn, reg: SpaceState, uniq: SpaceState,
                  global_syms: dict[int, Val], result: ExecResult,
                  solver: "claripy.Solver",
                  current_step: int = 0) -> Val:
        """Read a varnode value from the appropriate space."""
        sname = vn.space.name if vn.space else 'const'

        if sname == 'const':
            return vn.offset  # value IS the offset for const space

        if sname == 'register':
            return reg.read(vn.offset, vn.size)

        if sname == 'unique':
            return uniq.read(vn.offset, vn.size)

        if sname == 'ram':
            addr = vn.offset
            if addr in global_syms:
                return global_syms[addr]
            if self._is_global(addr):
                # First read of this global → create symbolic variable
                sym_name = f'global_{addr:#x}'
                bv = claripy.BVS(sym_name, _bits(vn.size))
                global_syms[addr] = bv
                result.global_reads[addr] = vn.size
                # P8: record which step this global was first accessed
                # Low step = guard/null-check; high step = deep compute field
                if addr not in result.global_first_step:
                    result.global_first_step[addr] = current_step
                if self.verbose:
                    print(f'  [pcode_sym] LOAD global {addr:#x} → {sym_name}')
                return bv
            # Code/rdata read: try to read from our bytes
            offset = addr - self.base_va
            if 0 <= offset < len(self.code) - vn.size + 1:
                raw = self.code[offset:offset+vn.size]
                return int.from_bytes(raw, 'little')
            return 0  # unmapped: return 0

        return 0

    def _write_vn(self, vn, val: Val, reg: SpaceState, uniq: SpaceState) -> None:
        """Write val to the appropriate space."""
        if vn is None:
            return
        sname = vn.space.name if vn.space else '?'
        if sname == 'register':
            reg.write(vn.offset, vn.size, val)
        elif sname == 'unique':
            uniq.write(vn.offset, vn.size, val)
        # ram writes: we don't track them (could add for STORE analysis)

    def _exec_op(self, op, reg: SpaceState, uniq: SpaceState,
                  global_syms: dict, result: ExecResult,
                  solver: "claripy.Solver",
                  add_constraint=None,
                  constraint_count_ref=None,
                  cbranch_hits: dict | None = None,
                  max_loop_iters: int = 4,
                  current_step: int = 0,
                  reg_taint: dict | None = None) -> tuple[int | None, bool]:
        if add_constraint is None:
            add_constraint = solver.add  # fallback: direct add, no complexity guard
        if constraint_count_ref is None:
            constraint_count_ref = [0]  # dummy
        if cbranch_hits is None:
            cbranch_hits = {}  # dummy
        if reg_taint is None:
            reg_taint = {}  # dummy
        """
        Execute one P-CODE op.
        Returns (next_va, stop):
          next_va = branch target if BRANCH/CBRANCH taken, else None
          stop    = True if execution should terminate (RETURN, unresolvable branch)
        """
        opc = op.opcode

        # Skip instruction markers
        if opc is OpCode.IMARK:
            return None, False

        def R(i=0): return self._read_vn(op.inputs[i], reg, uniq,
                                          global_syms, result, solver,
                                          current_step=current_step)
        def W(v):   self._write_vn(op.output, v, reg, uniq)
        def SZ():   return op.output.size if op.output else 1

        # ── Memory ────────────────────────────────────────────────────────────
        if opc is OpCode.COPY:
            val = R(0)
            W(val)
            # Taint propagation: if source is a direct .data global, taint dest
            src_vn = op.inputs[0]
            if (src_vn.space and src_vn.space.name == 'ram'
                    and self._is_global(src_vn.offset)
                    and op.output and op.output.space):
                reg_taint[(op.output.space.name, op.output.offset)] = (src_vn.offset, 0)
            elif op.output and op.output.space:
                key = (op.output.space.name, op.output.offset)
                # Propagate taint if source is already tainted
                if (src_vn.space and
                        (src_vn.space.name, src_vn.offset) in reg_taint):
                    reg_taint[key] = reg_taint[(src_vn.space.name, src_vn.offset)]
                else:
                    reg_taint.pop(key, None)

        elif opc is OpCode.LOAD:
            # inputs[0] = space id (const space, value = space id number)
            # inputs[1] = address to load from
            addr_vn = op.inputs[1]
            addr_val = R(1)
            out_size = op.output.size
            # TAINT CHECK FIRST — before the symbolic/concrete branch.
            # When addr_val is symbolic (e.g. global_ptr + 0x18 as a BV expression),
            # the taint tells us the concrete struct field. Don't let symbolism hide it.
            addr_taint_key = (addr_vn.space.name, addr_vn.offset) if addr_vn.space else None
            if addr_taint_key and addr_taint_key in reg_taint:
                base_global, field_offset = reg_taint[addr_taint_key]
                result.struct_field_reads.append((base_global, field_offset, out_size))
                if self.verbose:
                    print(f'  [pcode_sym] INDIRECT {base_global:#x}+{field_offset:#x}')
                bv = claripy.BVS(f'field_{base_global:#x}_{field_offset:#x}', _bits(out_size))
                W(bv)
                if op.output and op.output.space:
                    reg_taint[(op.output.space.name, op.output.offset)] = (base_global, field_offset)
            elif _is_sym(addr_val):
                W(claripy.BVS(f'mem_sym_{id(op):#x}', _bits(out_size)))
            else:
                addr = _concrete(addr_val, 8)
                if self._is_global(addr):
                    # DIRECT global read (the address itself is in .data)
                    sym_name = f'global_{addr:#x}'
                    if addr not in global_syms:
                        bv = claripy.BVS(sym_name, _bits(out_size))
                        global_syms[addr] = bv
                        result.global_reads[addr] = out_size
                        if addr not in result.global_first_step:
                            result.global_first_step[addr] = current_step
                        if self.verbose:
                            print(f'  [pcode_sym] LOAD global {addr:#x} → {sym_name}')
                    W(global_syms[addr])
                    # Taint the destination: this value IS the global pointer
                    if op.output and op.output.space:
                        reg_taint[(op.output.space.name, op.output.offset)] = (addr, 0)
                else:
                    offset = addr - self.base_va
                    if 0 <= offset < len(self.code) - out_size + 1:
                        raw = self.code[offset:offset+out_size]
                        W(int.from_bytes(raw, 'little'))
                    else:
                        W(0)

        elif opc is OpCode.STORE:
            # inputs[0] = space, inputs[1] = address, inputs[2] = value
            pass  # Don't track stores for now

        # ── Control flow ──────────────────────────────────────────────────────
        elif opc is OpCode.BRANCH:
            target_vn = op.inputs[0]
            if target_vn.space and target_vn.space.name == 'ram':
                return target_vn.offset, False
            return None, True  # indirect or unresolvable

        elif opc is OpCode.CBRANCH:
            target_vn = op.inputs[0]
            cond = R(1)
            cbranch_va_here = op.inputs[0].offset
            target = cbranch_va_here if (target_vn.space and
                                          target_vn.space.name == 'ram') else None

            # ── Loop detection: count how many times this CBRANCH fires ─────
            cbranch_hits[cbranch_va_here] = cbranch_hits.get(cbranch_va_here, 0) + 1
            if cbranch_hits[cbranch_va_here] > max_loop_iters:
                # We've been here before — this is a loop branch.
                # Record the condition but DON'T follow the branch target.
                # This breaks the loop and lets execution fall through to exit.
                msg = f"LOOP_BRANCH at {cbranch_va_here:#x} (fired {cbranch_hits[cbranch_va_here]}x)"
                result.silent_guesses.append(msg)
                if self.verbose:
                    print(f"  [pcode_sym] {msg} — stopping loop", file=sys.stderr)
                if _is_sym(cond):
                    result.constraints.append(GlobalConstraint(
                        addr=0, size=0, sym_name=str(cond),
                        constraint=cond, branch_taken=False,
                    ))
                return None, False  # fallthrough, don't follow back-edge

            if _is_sym(cond):
                cbranch_va = op.inputs[0].offset

                # ── Measure AST complexity before eval ──────────────────────
                ast_depth, ast_nodes = _ast_complexity(cond)
                n_solver_cons = constraint_count_ref[0]

                # Try to concretize via current solver state.
                # solver.timeout=5000ms prevents silent Z3 hang (default was 300000ms=5min!).
                import time as _t
                _eval_t0 = _t.perf_counter()
                timed_out = False
                try:
                    solutions = solver.eval(cond, 2)
                except Exception:
                    solutions = []
                    timed_out = True
                    msg = f"SOLVER_TIMEOUT at {cbranch_va:#x}"
                    result.silent_guesses.append(msg)
                    if self.verbose:
                        print(f"  [pcode_sym] {msg} — treating as ambiguous", file=sys.stderr)
                eval_ms = (_t.perf_counter() - _eval_t0) * 1000
                both_sat = len(solutions) >= 2

                # ── Record timing ────────────────────────────────────────────
                result.cbranch_timings.append(ConstraintTiming(
                    cbranch_va=cbranch_va, eval_ms=eval_ms,
                    ast_depth=ast_depth, ast_nodes=ast_nodes,
                    n_vars=len(cond.variables) if hasattr(cond,'variables') else 0,
                    n_solver_cons=n_solver_cons,
                    timed_out=timed_out, both_sat=both_sat,
                ))

                if len(solutions) == 1:
                    taken = bool(solutions[0])
                elif solutions:
                    taken = bool(solutions[0])
                    msg = f"CBRANCH_AMBIGUOUS at {cbranch_va:#x}"
                    result.silent_guesses.append(msg)
                    if self.verbose:
                        print(f"  [pcode_sym] {msg} — following taken={taken}", file=sys.stderr)
                else:
                    taken = True
                    if not timed_out:
                        msg = f"CBRANCH_UNSOLVABLE at {cbranch_va:#x}"
                        result.silent_guesses.append(msg)
                        print(f"  [pcode_sym] WARNING: {msg} — guessing taken=True", file=sys.stderr)
                result.constraints.append(GlobalConstraint(
                    addr=0, size=0, sym_name=str(cond),
                    constraint=cond, branch_taken=taken,
                ))
                # BUG TRAP: len(cond) is already BITS (claripy convention).
                cond_bits = len(cond)
                add_constraint(cond == claripy.BVV(int(taken), cond_bits))
                if taken and target is not None:
                    return target, False
            else:
                taken = bool(_concrete(cond, 1))
                if taken and target is not None:
                    return target, False
            return None, False  # fallthrough

        elif opc is OpCode.BRANCHIND:
            return None, True  # can't follow indirect branches statically

        elif opc is OpCode.RETURN:
            return None, True

        elif opc is OpCode.CALL:
            # Direct call: stub it (return 0)
            if op.inputs:
                target_vn = op.inputs[0]
                if target_vn.space and target_vn.space.name == 'ram':
                    result.stub_calls.append(target_vn.offset)
            # Set RAX = 0 as stub return value
            rax_key = self._reg_offsets.get('RAX')
            if rax_key:
                reg.write(rax_key[0], rax_key[1], 0)

        elif opc is OpCode.CALLIND:
            result.stub_calls.append(-1)
            rax_key = self._reg_offsets.get('RAX')
            if rax_key:
                reg.write(rax_key[0], rax_key[1], 0)

        elif opc is OpCode.CALLOTHER:
            # Architecture-specific (syscall, cpuid, etc.) — stub
            rax_key = self._reg_offsets.get('RAX')
            if rax_key:
                reg.write(rax_key[0], rax_key[1], 0)

        # ── Integer arithmetic ────────────────────────────────────────────────
        elif opc is OpCode.INT_ADD:
            a, b, sz = R(0), R(1), SZ()
            if _is_sym(a) or _is_sym(b):
                W((_to_bv(a, sz) + _to_bv(b, sz)))
            else:
                W((int(a) + int(b)) & _mask(sz))
            # Taint propagation: tainted_var + concrete_const → tainted result with updated offset
            # Covers both register and unique output spaces.
            if op.output and op.output.space:
                out_key = (op.output.space.name, op.output.offset)
                in0, in1 = op.inputs[0], op.inputs[1]
                taint_src = None
                concrete_add = None
                for vn in (in0, in1):
                    if vn.space and vn.space.name == 'const':
                        concrete_add = vn.offset
                    elif vn.space:
                        k = (vn.space.name, vn.offset)
                        if k in reg_taint:
                            taint_src = reg_taint[k]
                if taint_src is not None and concrete_add is not None:
                    base, old_off = taint_src
                    reg_taint[out_key] = (base, old_off + concrete_add)
                else:
                    reg_taint.pop(out_key, None)

        elif opc is OpCode.INT_SUB:
            a, b, sz = R(0), R(1), SZ()
            if _is_sym(a) or _is_sym(b):
                W(_to_bv(a, sz) - _to_bv(b, sz))
            else:
                W((int(a) - int(b)) & _mask(sz))
            # Taint propagation for subtraction (ptr - const = earlier field)
            if op.output and op.output.space:
                out_key = (op.output.space.name, op.output.offset)
                in0, in1 = op.inputs[0], op.inputs[1]
                in0_key = (in0.space.name, in0.offset) if in0.space else None
                if (in0_key and in0_key in reg_taint
                        and in1.space and in1.space.name == 'const'):
                    base, old_off = reg_taint[in0_key]
                    reg_taint[out_key] = (base, old_off - in1.offset)
                else:
                    reg_taint.pop(out_key, None)

        elif opc is OpCode.INT_MULT:
            a, b, sz = R(0), R(1), SZ()
            if _is_sym(a) or _is_sym(b):
                W(_to_bv(a, sz) * _to_bv(b, sz))
            else:
                W((int(a) * int(b)) & _mask(sz))

        elif opc is OpCode.INT_DIV:  # unsigned
            a, b, sz = R(0), R(1), SZ()
            if _is_sym(a) or _is_sym(b):
                bv_b = _to_bv(b, sz)
                add_constraint(bv_b != claripy.BVV(0, _bits(sz)))
                W(claripy.UDiv(_to_bv(a, sz), bv_b))
            else:
                bv = int(b) & _mask(sz)
                W((int(a) // bv) & _mask(sz) if bv else 0)

        elif opc is OpCode.INT_SDIV:  # signed
            a, b, sz = R(0), R(1), SZ()
            if _is_sym(a) or _is_sym(b):
                bv_b = _to_bv(b, sz)
                add_constraint(bv_b != claripy.BVV(0, _bits(sz)))
                W(_to_bv(a, sz) / bv_b)
            else:
                bv = int(b) & _mask(sz)
                W(_sext(int(a), sz, sz) // _sext(bv, sz, sz) if bv else 0)

        elif opc is OpCode.INT_REM:   # unsigned remainder
            a, b, sz = R(0), R(1), SZ()
            if _is_sym(a) or _is_sym(b):
                bv_b = _to_bv(b, sz)
                add_constraint(bv_b != claripy.BVV(0, _bits(sz)))
                W(claripy.URem(_to_bv(a, sz), bv_b))
            else:
                bv = int(b) & _mask(sz)
                W((int(a) % bv) & _mask(sz) if bv else 0)

        elif opc is OpCode.INT_SREM:  # signed remainder
            a, b, sz = R(0), R(1), SZ()
            if _is_sym(a) or _is_sym(b):
                bv_b = _to_bv(b, sz)
                add_constraint(bv_b != claripy.BVV(0, _bits(sz)))
                W(claripy.SRem(_to_bv(a, sz), bv_b))
            else:
                bv = int(b) & _mask(sz)
                W(_sext(int(a), sz, sz) % _sext(bv, sz, sz) if bv else 0)

        elif opc is OpCode.INT_AND:
            a, b, sz = R(0), R(1), SZ()
            W(_to_bv(a, sz) & _to_bv(b, sz) if (_is_sym(a) or _is_sym(b))
              else (int(a) & int(b)) & _mask(sz))

        elif opc is OpCode.INT_OR:
            a, b, sz = R(0), R(1), SZ()
            W(_to_bv(a, sz) | _to_bv(b, sz) if (_is_sym(a) or _is_sym(b))
              else (int(a) | int(b)) & _mask(sz))

        elif opc is OpCode.INT_XOR:
            a, b, sz = R(0), R(1), SZ()
            W(_to_bv(a, sz) ^ _to_bv(b, sz) if (_is_sym(a) or _is_sym(b))
              else (int(a) ^ int(b)) & _mask(sz))

        elif opc is OpCode.INT_NEGATE:  # bitwise NOT
            a, sz = R(0), SZ()
            W(~_to_bv(a, sz) if _is_sym(a) else (~int(a)) & _mask(sz))

        elif opc is OpCode.INT_2COMP:  # two's complement (negation)
            a, sz = R(0), SZ()
            W(-_to_bv(a, sz) if _is_sym(a) else (-int(a)) & _mask(sz))

        elif opc is OpCode.INT_LEFT:
            a, b, sz = R(0), R(1), SZ()
            W(_to_bv(a, sz) << _to_bv(b, sz) if (_is_sym(a) or _is_sym(b))
              else (int(a) << (int(b) & 63)) & _mask(sz))

        elif opc is OpCode.INT_RIGHT:  # unsigned right shift
            a, b, sz = R(0), R(1), SZ()
            W(claripy.LShR(_to_bv(a, sz), _to_bv(b, sz))
              if (_is_sym(a) or _is_sym(b))
              else (int(a) & _mask(sz)) >> (int(b) & 63))

        elif opc is OpCode.INT_SRIGHT:  # arithmetic right shift (signed)
            a, b, sz = R(0), R(1), SZ()
            W(_to_bv(a, sz) >> _to_bv(b, sz) if (_is_sym(a) or _is_sym(b))
              else _sext(int(a), sz, sz) >> (int(b) & 63))

        elif opc is OpCode.INT_EQUAL:
            a, b, sz = R(0), R(1), op.inputs[0].size
            if _is_sym(a) or _is_sym(b):
                W(claripy.If(_to_bv(a, sz) == _to_bv(b, sz),
                             claripy.BVV(1, 8), claripy.BVV(0, 8)))
            else:
                W(1 if (int(a) & _mask(sz)) == (int(b) & _mask(sz)) else 0)

        elif opc is OpCode.INT_NOTEQUAL:
            a, b, sz = R(0), R(1), op.inputs[0].size
            if _is_sym(a) or _is_sym(b):
                W(claripy.If(_to_bv(a, sz) != _to_bv(b, sz),
                             claripy.BVV(1, 8), claripy.BVV(0, 8)))
            else:
                W(1 if (int(a) & _mask(sz)) != (int(b) & _mask(sz)) else 0)

        elif opc is OpCode.INT_LESS:  # unsigned less-than
            a, b, sz = R(0), R(1), op.inputs[0].size
            if _is_sym(a) or _is_sym(b):
                W(claripy.If(claripy.ULT(_to_bv(a, sz), _to_bv(b, sz)),
                             claripy.BVV(1, 8), claripy.BVV(0, 8)))
            else:
                W(1 if (int(a) & _mask(sz)) < (int(b) & _mask(sz)) else 0)

        elif opc is OpCode.INT_LESSEQUAL:  # unsigned ≤
            a, b, sz = R(0), R(1), op.inputs[0].size
            if _is_sym(a) or _is_sym(b):
                W(claripy.If(claripy.ULE(_to_bv(a, sz), _to_bv(b, sz)),
                             claripy.BVV(1, 8), claripy.BVV(0, 8)))
            else:
                W(1 if (int(a) & _mask(sz)) <= (int(b) & _mask(sz)) else 0)

        elif opc is OpCode.INT_SLESS:  # signed less-than
            a, b, sz = R(0), R(1), op.inputs[0].size
            if _is_sym(a) or _is_sym(b):
                W(claripy.If(claripy.SLT(_to_bv(a, sz), _to_bv(b, sz)),
                             claripy.BVV(1, 8), claripy.BVV(0, 8)))
            else:
                W(1 if _sext(int(a), sz, sz) < _sext(int(b), sz, sz) else 0)

        elif opc is OpCode.INT_SLESSEQUAL:  # signed ≤
            a, b, sz = R(0), R(1), op.inputs[0].size
            if _is_sym(a) or _is_sym(b):
                W(claripy.If(claripy.SLE(_to_bv(a, sz), _to_bv(b, sz)),
                             claripy.BVV(1, 8), claripy.BVV(0, 8)))
            else:
                W(1 if _sext(int(a), sz, sz) <= _sext(int(b), sz, sz) else 0)

        elif opc is OpCode.INT_CARRY:  # unsigned carry (addition overflow)
            # Reference: jevinskie/pypcode-emu emu.py Int.carry()
            # Verified: (a + b) > MAX_UNSIGNED means unsigned overflow
            a, b, sz = R(0), R(1), op.inputs[0].size
            if _is_sym(a) or _is_sym(b):
                # Extend by 8 bits, add, check if high bit set
                full = claripy.ZeroExt(8, _to_bv(a, sz)) + claripy.ZeroExt(8, _to_bv(b, sz))
                W(claripy.LShR(full, _bits(sz)) & claripy.BVV(1, _bits(sz)+8))
            else:
                W(1 if (int(a) + int(b)) > _mask(sz) else 0)

        elif opc is OpCode.INT_SCARRY:  # signed carry (signed addition overflow)
            # Reference: naaz/executor/PCodeExecutor.cpp csleigh_CPUI_INT_SCARRY
            # Reference: jevinskie/pypcode-emu scripts/z3_sandbox.py scarry_z3()
            # Formula: overflow iff sign(a)==sign(b) AND sign(result)!=sign(a)
            # i.e. adding two positives gives negative, or two negatives give positive
            # VERIFIED against z3_sandbox.py test cases (see scripts/z3_sandbox.py)
            a, b, sz = R(0), R(1), op.inputs[0].size
            bits = _bits(sz)
            if _is_sym(a) or _is_sym(b):
                va, vb = _to_bv(a, sz), _to_bv(b, sz)
                res = va + vb
                sign_a = claripy.Extract(bits-1, bits-1, va)
                sign_b = claripy.Extract(bits-1, bits-1, vb)
                sign_r = claripy.Extract(bits-1, bits-1, res)
                # (sign_a ^ sign_b ^ 1) = 1 when signs match; & (sign_a ^ sign_r) = overflow
                overflow = (sign_a ^ sign_b ^ claripy.BVV(1,1)) & (sign_a ^ sign_r)
                W(overflow)
            else:
                # Concrete: widen to n+1 signed bits, check range
                ia = _sext(int(a), sz, sz+1)
                ib = _sext(int(b), sz, sz+1)
                s = ia + ib
                W(0 if -(1 << (_bits(sz)-1)) <= s <= (1 << (_bits(sz)-1))-1 else 1)

        elif opc is OpCode.INT_SBORROW:  # signed borrow (signed subtraction overflow)
            # Reference: naaz/executor/PCodeExecutor.cpp csleigh_CPUI_INT_SBORROW
            # Formula: overflow iff sign(a)!=sign(b) AND sign(result)!=sign(a)
            # i.e. subtracting in a way that wraps the signed range
            # Note: differs from INT_SCARRY only in the first factor (XOR not XNOR)
            a, b, sz = R(0), R(1), op.inputs[0].size
            bits = _bits(sz)
            if _is_sym(a) or _is_sym(b):
                va, vb = _to_bv(a, sz), _to_bv(b, sz)
                res = va - vb
                sign_a = claripy.Extract(bits-1, bits-1, va)
                sign_b = claripy.Extract(bits-1, bits-1, vb)
                sign_r = claripy.Extract(bits-1, bits-1, res)
                overflow = (sign_a ^ sign_b) & (sign_a ^ sign_r)
                W(overflow)
            else:
                ia = _sext(int(a), sz, sz+1)
                ib = _sext(int(b), sz, sz+1)
                s = ia - ib
                W(0 if -(1 << (_bits(sz)-1)) <= s <= (1 << (_bits(sz)-1))-1 else 1)

        elif opc is OpCode.INT_ZEXT:
            a = R(0); in_sz = op.inputs[0].size; out_sz = SZ()
            if _is_sym(a):
                W(claripy.ZeroExt(_bits(out_sz) - _bits(in_sz), _to_bv(a, in_sz)))
            else:
                W(int(a) & _mask(in_sz))

        elif opc is OpCode.INT_SEXT:
            a = R(0); in_sz = op.inputs[0].size; out_sz = SZ()
            if _is_sym(a):
                W(claripy.SignExt(_bits(out_sz) - _bits(in_sz), _to_bv(a, in_sz)))
            else:
                W(_sext(int(a), in_sz, out_sz))

        # ── Boolean ops (1-bit) ───────────────────────────────────────────────
        elif opc is OpCode.BOOL_NEGATE:
            a = R(0)
            if _is_sym(a):
                W(~_to_bv(a, 1) & claripy.BVV(1, _bits(SZ())))
            else:
                W(0 if int(a) else 1)

        elif opc is OpCode.BOOL_AND:
            a, b = R(0), R(1)
            if _is_sym(a) or _is_sym(b):
                W(_to_bv(a, 1) & _to_bv(b, 1))
            else:
                W(1 if int(a) and int(b) else 0)

        elif opc is OpCode.BOOL_OR:
            a, b = R(0), R(1)
            if _is_sym(a) or _is_sym(b):
                W(_to_bv(a, 1) | _to_bv(b, 1))
            else:
                W(1 if int(a) or int(b) else 0)

        elif opc is OpCode.BOOL_XOR:
            a, b = R(0), R(1)
            if _is_sym(a) or _is_sym(b):
                W(_to_bv(a, 1) ^ _to_bv(b, 1))
            else:
                W(1 if bool(int(a)) ^ bool(int(b)) else 0)

        # ── Bit manipulation ──────────────────────────────────────────────────
        elif opc is OpCode.SUBPIECE:
            # Reference: jevinskie/pypcode-emu emu.py subpiece() + Int.subpiece()
            # Reference: naaz/executor/PCodeExecutor.cpp csleigh_CPUI_SUBPIECE
            # inputs[0] = source, inputs[1] = CONST: byte offset from low end to start truncating
            # Semantics: take out_sz bytes starting at byte_offset of source
            # e.g. SUBPIECE(RAX:8, 4:4) → upper 4 bytes of RAX
            # Note: inputs[1] is ALWAYS a const varnode in practice
            a = R(0); byte_offset = _concrete(R(1), 4); in_sz = op.inputs[0].size; out_sz = SZ()
            if _is_sym(a):
                lo_bit = byte_offset * 8
                hi_bit = lo_bit + _bits(out_sz) - 1
                W(claripy.Extract(hi_bit, lo_bit, _to_bv(a, in_sz)))
            else:
                W((int(a) >> (byte_offset * 8)) & _mask(out_sz))

        elif opc is OpCode.PIECE:
            # Reference: Ghidra P-CODE reference manual — PIECE concatenates two varnodes
            # inputs[0]=most-significant half, inputs[1]=least-significant half
            # Output width = input[0].size + input[1].size
            a = R(0); b = R(1); hi_sz = op.inputs[0].size; lo_sz = op.inputs[1].size; out_sz = SZ()
            if _is_sym(a) or _is_sym(b):
                W(claripy.Concat(_to_bv(a, hi_sz), _to_bv(b, lo_sz)))
            else:
                W(((int(a) & _mask(hi_sz)) << _bits(lo_sz)) | (int(b) & _mask(lo_sz)))

        elif opc is OpCode.POPCOUNT:
            a = R(0); sz = SZ()
            if _is_sym(a):
                # Expand symbolically (expensive but correct)
                bits = _bits(op.inputs[0].size)
                result_bv = claripy.BVV(0, _bits(sz))
                for i in range(bits):
                    bit_i = claripy.Extract(i, i, _to_bv(a, op.inputs[0].size))
                    result_bv = result_bv + claripy.ZeroExt(_bits(sz)-1, bit_i)
                W(result_bv)
            else:
                W(_popcount(int(a) & _mask(op.inputs[0].size)))

        elif opc is OpCode.LZCOUNT:
            a = R(0); sz = SZ()
            if _is_sym(a):
                W(claripy.BVS(f'lzcount_{id(op):#x}', _bits(sz)))  # stub symbolically
            else:
                v = int(a) & _mask(op.inputs[0].size)
                bits = _bits(op.inputs[0].size)
                W(bits - v.bit_length() if v else bits)

        # ── Float ops — Sign Abstract Domain (not full IEEE 754 symbolic) ────────
        # Full FP symbolic via claripy.FPS costs 118-335ms per Z3 call (10-20x BV).
        # For loop termination patterns, sign suffices: FLOAT_GT(POSITIVE, 0) → True.
        # We track signs as FSign objects propagating through float arithmetic.
        # This gives deterministic CBRANCH decisions for common patterns without Z3.
        # Ref: Sign Abstract Domain, Cousot & Cousot 1977 Abstract Interpretation.
        elif opc is OpCode.FLOAT_INT2FLOAT:
            a = R(0); in_sz = op.inputs[0].size
            # Convert int/symbolic to float sign domain
            if _is_sym(a):
                W(_FSIGN_UNK)  # symbolic int → unknown sign
            else:
                W(_fsign(int(a) if not _is_sym(a) else a))

        elif opc is OpCode.FLOAT_FLOAT2FLOAT:
            a = R(0)
            W(a if isinstance(a, FSign) else _FSIGN_UNK)

        elif opc is OpCode.FLOAT_TRUNC:
            # Trunc: sign preserved, result is int (but we keep sign for propagation)
            a = R(0)
            if isinstance(a, FSign):
                # Convert back to concrete int based on sign (rough approximation)
                if a.sign == 'POS': W(1)
                elif a.sign == 'NEG': W(-1)
                elif a.sign == 'ZERO': W(0)
                else: W(0)  # UNK → 0 (logged)
            else:
                W(0)

        elif opc in (OpCode.FLOAT_ADD, OpCode.FLOAT_SUB):
            a, b = R(0), R(1)
            fa = a if isinstance(a, FSign) else _FSIGN_UNK
            fb = b if isinstance(b, FSign) else _FSIGN_UNK
            if opc is OpCode.FLOAT_SUB:
                fb = _fsign_neg(fb)
            W(_fsign_add(fa, fb))

        elif opc is OpCode.FLOAT_MULT:
            a, b = R(0), R(1)
            fa = a if isinstance(a, FSign) else _FSIGN_UNK
            fb = b if isinstance(b, FSign) else _FSIGN_UNK
            W(_fsign_mul(fa, fb))

        elif opc is OpCode.FLOAT_DIV:
            a, b = R(0), R(1)
            fa = a if isinstance(a, FSign) else _FSIGN_UNK
            fb = b if isinstance(b, FSign) else _FSIGN_UNK
            # sign(a/b) = sign(a) * sign(b)
            W(_fsign_mul(fa, fb))

        elif opc is OpCode.FLOAT_NEG:
            a = R(0)
            W(_fsign_neg(a if isinstance(a, FSign) else _FSIGN_UNK))

        elif opc is OpCode.FLOAT_ABS:
            a = R(0)
            fa = a if isinstance(a, FSign) else _FSIGN_UNK
            W(_FSIGN_ZERO if fa.sign == 'ZERO' else _FSIGN_POS if fa.sign != 'UNK' else _FSIGN_UNK)

        elif opc is OpCode.FLOAT_SQRT:
            a = R(0)
            fa = a if isinstance(a, FSign) else _FSIGN_UNK
            W(_FSIGN_ZERO if fa.sign == 'ZERO' else _FSIGN_POS if fa.sign == 'POS' else _FSIGN_UNK)

        elif opc is OpCode.FLOAT_EQUAL:
            a, b = R(0), R(1)
            fa = a if isinstance(a, FSign) else _FSIGN_UNK
            fb = b if isinstance(b, FSign) else _FSIGN_UNK
            # Only certain if both ZERO
            if fa.sign == 'ZERO' and fb.sign == 'ZERO': W(1)
            elif fa.sign != 'UNK' and fb.sign != 'UNK' and fa.sign != fb.sign: W(0)
            else: W(0)  # unknown → 0

        elif opc is OpCode.FLOAT_NOTEQUAL:
            a, b = R(0), R(1)
            fa = a if isinstance(a, FSign) else _FSIGN_UNK
            fb = b if isinstance(b, FSign) else _FSIGN_UNK
            if fa.sign != 'UNK' and fb.sign != 'UNK' and fa.sign != fb.sign: W(1)
            elif fa.sign == 'ZERO' and fb.sign == 'ZERO': W(0)
            else: W(0)

        elif opc is OpCode.FLOAT_LESS:
            # a < b: check if sign(a) < sign(b)
            a, b = R(0), R(1)
            fa = a if isinstance(a, FSign) else _FSIGN_UNK
            fb = b if isinstance(b, FSign) else _FSIGN_UNK
            result_val = _fsign_gt_zero(_fsign_add(fb, _fsign_neg(fa)))  # b-a > 0
            W(1 if result_val is True else 0)

        elif opc is OpCode.FLOAT_LESSEQUAL:
            a, b = R(0), R(1)
            fa = a if isinstance(a, FSign) else _FSIGN_UNK
            fb = b if isinstance(b, FSign) else _FSIGN_UNK
            result_val = _fsign_gt_zero(_fsign_neg(fa))  # a ≤ b ↔ ¬(a>b)
            W(1 if result_val is not False else 0)

        elif opc is OpCode.FLOAT_NAN:
            W(0)  # assume not NaN (normal numbers in most programs)

        elif opc in (OpCode.FLOAT_CEIL, OpCode.FLOAT_FLOOR, OpCode.FLOAT_ROUND):
            a = R(0)
            fa = a if isinstance(a, FSign) else _FSIGN_UNK
            # Sign preserved under rounding
            W(fa)

        # ── High P-CODE (should NOT appear in raw bytes — if seen, something is wrong) ──
        # MULTIEQUAL/INDIRECT are SSA phi-nodes that only exist in Ghidra's
        # high P-CODE (decompiler output). If we see them in raw translation,
        # it means our translate() call is somehow using high P-CODE, which is
        # wrong. Flag loudly.
        elif opc in (OpCode.MULTIEQUAL, OpCode.INDIRECT, OpCode.PTRADD,
                     OpCode.PTRSUB, OpCode.CAST, OpCode.SEGMENTOP,
                     OpCode.CPOOLREF, OpCode.NEW, OpCode.INSERT,
                     OpCode.ZPULL, OpCode.SPULL):
            msg = f"HIGH_PCODE_OP:{opc.name} (should not appear in raw P-CODE)"
            result.unimpl_ops.append(msg)
            result.silent_guesses.append(msg)
            print(f"  [pcode_sym] WARNING: {msg} — result confidence LOW", file=sys.stderr)
            if op.output:
                W(0)

        else:
            # Truly unknown: record loudly. Do NOT silently return 0 without telling caller.
            msg = f"UNKNOWN_OP:{opc.name}"
            result.unimpl_ops.append(msg)
            result.silent_guesses.append(msg)
            print(f"  [pcode_sym] WARNING: {msg} — stubbing to 0, result confidence LOW",
                  file=sys.stderr)
            if op.output:
                W(0)

        return None, False

    # Max constraints before resetting solver. Above this Z3 gets slow fast.
    # Empirically: functions with many globals accumulate 50+ constraints in tight loops.
    MAX_SOLVER_CONSTRAINTS = 30

    def run(
        self,
        entry_va:     int,
        initial_regs: dict[str, int] | None = None,
        max_steps:    int = MAX_STEPS,
        wall_timeout: float = 10.0,   # per-function wall-clock timeout in seconds
    ) -> ExecResult:
        """
        Execute from entry_va symbolically.
        initial_regs: {'RCX': 0x1000, 'RSP': 0x7ff00000, ...}
        wall_timeout: hard kill after N seconds regardless of solver state.
        """
        import time as _time
        result   = ExecResult(ok=False)
        reg      = SpaceState('register')
        global_syms: dict[int, Val] = {}
        _wall_start = _time.perf_counter()

        def _make_fresh_solver() -> "claripy.Solver":
            s = claripy.Solver()
            # TRANSPARENCY: default=300000ms (5 min!). We set 5s.
            # On timeout, claripy raises ClaripySolverInterruptError.
            s.timeout = 5000
            return s

        solver = _make_fresh_solver()
        _solver_constraint_count = [0]   # mutable counter for constraint tracking

        def _add_constraint(formula) -> None:
            """Add a constraint with complexity guard — reset solver if too deep."""
            nonlocal solver
            _solver_constraint_count[0] += 1
            if _solver_constraint_count[0] > self.MAX_SOLVER_CONSTRAINTS:
                msg = f"SOLVER_RESET after {_solver_constraint_count[0]} constraints"
                result.silent_guesses.append(msg)
                result.solver_resets += 1
                if self.verbose:
                    print(f"  [pcode_sym] {msg}", file=sys.stderr)
                solver = _make_fresh_solver()
                _solver_constraint_count[0] = 0
            solver.add(formula)

        def _check_wall_timeout() -> bool:
            """Returns True if we've exceeded the wall-clock timeout."""
            elapsed = _time.perf_counter() - _wall_start
            if elapsed > wall_timeout:
                msg = f"WALL_TIMEOUT after {elapsed:.1f}s"
                result.silent_guesses.append(msg)
                print(f"  [pcode_sym] WARNING: {msg} for {entry_va:#x}", file=sys.stderr)
                return True
            return False

        # Set initial register state
        for name, val in (initial_regs or {}).items():
            off_sz = self._reg_offsets.get(name.upper())
            if off_sz:
                reg.write(off_sz[0], off_sz[1], val)

        pc = entry_va
        steps = 0
        # Taint tracking for direct vs indirect global access.
        # Tracks: (global_base_addr, concrete_field_offset) per address variable.
        # Keyed by (space_name, offset) to cover both register and unique spaces.
        # P-CODE flow: COPY ram[global]→reg → INT_ADD reg+const→unique → LOAD unique→out
        # We track taint through all three steps.
        reg_taint: dict[tuple[str,int], tuple[int, int]] = {}  # (space,offset)→(base,field_off)

        # Loop detection: track how many times each CBRANCH VA fires.
        # If a CBRANCH fires >MAX_LOOP_ITERS times, we're in a loop.
        # Stop following it and record the loop condition as a LOOP_BRANCH.
        _cbranch_hits: dict[int, int] = {}
        MAX_LOOP_ITERS = 4  # after 4 trips through the same branch, declare a loop

        while pc is not None and steps < max_steps and not _check_wall_timeout():
            uniq = SpaceState('unique')  # fresh per-instruction group
            ops  = self._translate(pc)
            result.translate_calls += 1
            if not ops:
                break

            next_pc = pc + sum(
                (v.size for op in ops if op.opcode is OpCode.IMARK
                 for v in op.inputs), 0
            ) or pc + 4  # rough fallthrough

            # Find the actual fallthrough by looking at IMARK sizes
            imark_ends = [pc]
            for op in ops:
                if op.opcode is OpCode.IMARK and op.inputs:
                    imark_ends.append(op.inputs[0].offset + op.inputs[0].size)
            next_pc = max(imark_ends) if len(imark_ends) > 1 else pc + 4

            branch_target = None
            stop = False

            for op in ops:
                # Reset unique space at each IMARK (instruction boundary)
                if op.opcode is OpCode.IMARK:
                    uniq.reset()

                target, stop = self._exec_op(op, reg, uniq, global_syms, result, solver,
                                              add_constraint=_add_constraint,
                                              constraint_count_ref=_solver_constraint_count,
                                              cbranch_hits=_cbranch_hits,
                                              max_loop_iters=MAX_LOOP_ITERS,
                                              current_step=steps,
                                              reg_taint=reg_taint)
                if target is not None:
                    branch_target = target
                if stop:
                    break

            steps += 1
            for op in ops:
                if op.opcode.name != 'IMARK':
                    result.ops_histogram[op.opcode.name] = \
                        result.ops_histogram.get(op.opcode.name, 0) + 1

            if stop:
                break
            pc = branch_target if branch_target is not None else next_pc

            # Stop if we leave the function's code range
            if not (self.base_va <= pc < self.end_va):
                break

        result.ok = True
        result.steps_taken = steps
        result.elapsed_ms = (_time.perf_counter() - _wall_start) * 1000
        return result


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse, json
    ap = argparse.ArgumentParser(description="P-CODE symbolic executor")
    ap.add_argument("--dll",      required=True, help="Path to DLL/binary")
    ap.add_argument("--calltree", required=True)
    ap.add_argument("--func",     required=True, help="Function name")
    ap.add_argument("--arch",     default="x86:LE:64:default")
    ap.add_argument("--verbose",  action="store_true")
    args = ap.parse_args()

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    import ctypes
    from dynamic.execute import DLLExecutor
    from pe_utils import PE

    pe = PE(args.dll)
    executor = DLLExecutor(args.dll)
    rebase = executor.load_base - pe.image_base

    with open(args.calltree, encoding="utf-8") as f:
        ct = json.load(f)
    fns = {fn["name"]: fn for fn in ct["functions"]}

    fn = fns.get(args.func)
    if not fn:
        print(f"Function not found: {args.func!r}")
        return

    va     = int(fn["va"], 16)
    size   = fn["size"]

    # Read function bytes from the loaded DLL
    runtime_va = va + rebase
    code_bytes = bytes((ctypes.c_uint8 * size).from_address(runtime_va))

    # Global ranges: writable sections
    _WRITE = 0x80000000
    global_ranges = []
    for s in pe.sections:
        if s["vsize"] > 0 and (s["chars"] & _WRITE):
            lo = pe.image_base + s["vrva"]
            hi = lo + s["vsize"]
            global_ranges.append((lo, hi))

    print(f"Function: {args.func}  VA={va:#x}  size={size}")
    print(f"Global ranges: {[(hex(lo), hex(hi)) for lo,hi in global_ranges]}")

    exe = PCODESymEx(args.arch, code_bytes, va,
                     global_ranges=global_ranges, verbose=args.verbose)
    result = exe.run(va, initial_regs={"RSP": 0x7FF00000, "RCX": 0x1000})

    print(f"\nResult: ok={result.ok}")
    print(f"Global reads ({len(result.global_reads)}): "
          f"{[hex(a) for a in result.global_reads]}")
    print(f"Stub calls ({len(result.stub_calls)}): "
          f"{[hex(a) for a in result.stub_calls if a >= 0]}")
    print(f"Constraints ({len(result.constraints)}):")
    for c in result.constraints:
        print(f"  taken={c.branch_taken}  cond={c.sym_name[:80]}")
    if result.unimpl_ops:
        print(f"Unimplemented ops: {set(result.unimpl_ops)}")


if __name__ == "__main__":
    main()
