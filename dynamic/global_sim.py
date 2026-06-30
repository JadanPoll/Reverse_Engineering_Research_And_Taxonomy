"""
dynamic/global_sim.py — Global state inference and coverage-guided simulation.

Solves the "global init runtime problem": functions that read from globals populated
by deep init chains (mGBAInit, Py_Initialize, etc.) can't be simulated in isolation
because those globals are 0/unmapped in our controlled Unicorn environment.

Solution: invert the problem.
  Instead of: run init chain → globals populated → simulate function
  Do:         simulate with tracked stubs → observe which globals gate which paths
              → genetic mutation of stub values → recover required global state
              → Z3-solve exact branch conditions → complete characterization

Three layers:
  1. GlobalTrackingSim  — tracks which globals a function reads, returns stub values
  2. StubMutator        — genetic hill-climbing: find stub values that unlock new coverage
  3. Z3BranchSolver     — for each uncovered branch condition, solve analytically with Z3

Prior art:
  angr (full-program, heavy) — use for one-off discovery
  TritonDSE (concolic) — heavier but richer; defer unless hill-climbing fails
  This module: lightweight, purpose-built for our slice_sim integration

Usage:
    sim = GlobalTrackingSim(dll_path, calltree_path)
    spec = sim.classify(fn_entry)
    if spec.simulable:
        state = sim.infer_required_globals(spec)  # find what globals matter
        profile = sim.sweep_with_globals(spec, state)  # characterize with good state
"""
from __future__ import annotations
import sys, os, math, random, time
from collections import defaultdict, Counter
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dynamic.slice_sim import (SliceSim, SliceSpec, ProbeResult,
                               STACK_BASE, INPUT_BASE, INPUT_SIZE,
                               OUTPUT_BASE, OUTPUT_SIZE)

try:
    import unicorn as uc
    import unicorn.x86_const as x86
    _HAS_UNICORN = True
except ImportError:
    _HAS_UNICORN = False

try:
    import z3
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


# ── Global stub tracking ──────────────────────────────────────────────────────

@dataclass
class GlobalRead:
    """One global memory read that hit an unmapped/stub region."""
    address:     int       # runtime address read from
    size:        int       # bytes read (1, 2, 4, or 8)
    stub_value:  int       # value we returned (default 0)
    ghidra_va:   int       # Ghidra VA if address is in DLL, else -1


@dataclass
class CoverageResult:
    """Result of one probe with coverage tracking."""
    input_data:   bytes
    global_stubs: dict[int, int]     # {runtime_addr: stub_value_used}
    output_data:  bytes
    rax:          int
    coverage:     frozenset[int]     # basic block addresses hit
    global_reads: list[GlobalRead]   # all global reads observed
    elapsed_us:   float
    ok:           bool


class GlobalTrackingSim(SliceSim):
    """
    Extends SliceSim to track global memory reads and return controlled stub values.

    When a function reads from an address outside the PE sections (globals, heap,
    OS data), we return a configurable stub value instead of crashing/returning 0.
    This lets us:
    1. Observe which globals the function reads (coverage of global dependencies)
    2. Mutate stub values to discover which globals affect code paths
    3. Feed that state information to Z3 for exact constraint solving
    """

    def __init__(self, dll_path: str, calltree_path: str | None = None):
        if not _HAS_UNICORN:
            raise ImportError("pip install unicorn")
        super().__init__(dll_path, calltree_path)

        # Qiling-style: pre-map ALL sections (including writable) with zeros.
        # UC_HOOK_MEM_READ_UNMAPPED is buggy (unicorn issue #793) — returning True
        # from the hook is unreliable. Instead, pre-map writable sections with zeros
        # and use UC_HOOK_MEM_READ (fires on all reads) to track global accesses.
        import ctypes as _ctypes
        from dynamic.slice_sim import _PEMapper, _MuEnv
        _WRITE = 0x80000000

        # Track writable section ranges for filtering read events
        lb = self.executor.load_base
        self._writable_ranges: list[tuple[int, int]] = []  # (ghidra_va_lo, ghidra_va_hi)
        for s in self.pe.sections:
            if s["vsize"] > 0 and (s["chars"] & _WRITE):
                lo = self.pe.image_base + s["vrva"]
                hi = lo + s["vsize"]
                self._writable_ranges.append((lo, hi))

        # Build a new Unicorn env that maps ALL sections (code + data)
        # Data sections are filled with zeros (not live .data values)
        class _ZeroDataMapper(_PEMapper):
            """Maps code sections normally, data sections with zeros."""
            def map_sections(self_m, mu):
                for s in self_m.pe.sections:
                    if s["vsize"] == 0:
                        continue
                    ghidra_va = self_m.pe.image_base + s["vrva"]
                    mapped_sz = (s["vsize"] + 0xFFF) & ~0xFFF
                    runtime_va = self_m.load_base + s["vrva"]
                    try:
                        mu.mem_map(ghidra_va, mapped_sz)
                        if s["chars"] & _WRITE:
                            # Writable (data/bss): pre-map with zeros
                            mu.mem_write(ghidra_va, b"\x00" * s["vsize"])
                        else:
                            # Code/rdata: copy from loaded DLL
                            data = bytes((_ctypes.c_uint8 * s["vsize"]).from_address(runtime_va))
                            mu.mem_write(ghidra_va, data)
                    except Exception:
                        pass

        zero_mapper = _ZeroDataMapper(self.pe, lb)
        self._env_globals = _MuEnv(zero_mapper)

        # Rebase: runtime_addr = ghidra_va + self._rebase
        self._rebase = lb - self.pe.image_base

        # Build VA → function lookup from calltree
        self._va_to_fn: dict[int, dict] = {}
        for fn in self._fns.values():
            try:
                va = int(fn["va"], 16) if isinstance(fn["va"], str) else int(fn["va"])
                self._va_to_fn[va] = fn
            except Exception:
                pass

        # DLL address range (Ghidra VAs, i.e. image_base-relative)
        self._dll_gva_lo = self.pe.image_base
        self._dll_gva_hi = self.pe.image_base + max(
            (s["vrva"] + s["vsize"] for s in self.pe.sections if s["vsize"] > 0),
            default=0x10000,
        )

    # ── helpers ───────────────────────────────────────────────────────────────

    def _fn_at(self, ghidra_va: int) -> dict | None:
        """Return calltree function dict for a given Ghidra VA, or None."""
        return self._va_to_fn.get(ghidra_va)

    def _in_dll(self, runtime_addr: int) -> bool:
        """True if runtime_addr falls inside any loaded DLL section."""
        gva = runtime_addr - self._rebase
        return self._dll_gva_lo <= gva < self._dll_gva_hi

    def _to_ghidra(self, runtime_addr: int) -> int:
        """Convert a runtime address to Ghidra VA."""
        return runtime_addr - self._rebase

    def _run_with_tracking(
        self,
        spec:         SliceSpec,
        input_data:   bytes,
        global_stubs: dict[int, int] | None = None,
        max_instrs:   int = 1_000_000,
        extra_regs:   dict[str, int] | None = None,
    ) -> CoverageResult:
        """
        Run function with global read tracking + configurable stub values.

        global_stubs: {runtime_address: value_to_return}
        Any unmapped read NOT in global_stubs returns 0.
        """
        global_stubs = global_stubs or {}
        env = self._env_globals  # code-only env: .data reads become stubs
        env.reset_io(input_data)
        base_regs = {"rcx": INPUT_BASE, "rdx": len(input_data),
                     "r8": OUTPUT_BASE, "r9": 0}
        if extra_regs:
            base_regs.update(extra_regs)
        env.set_registers(base_regs)
        mu = env.mu

        global_reads_observed: list[GlobalRead] = []
        coverage: set[int] = set()
        writable = self._writable_ranges

        def _hook_block(mu, addr, size, _):
            coverage.add(addr)

        def _hook_mem_read(mu, access, addr, size, value, _):
            # Only track reads to writable (data/bss) sections — these are DLL globals.
            # Reads to code/.rdata are structural; reads to INPUT/OUTPUT are our probes.
            # Uses UC_HOOK_MEM_READ (fires on ALL reads) — reliable unlike UNMAPPED hook.
            for lo, hi in writable:
                if lo <= addr < hi:
                    stub_val = global_stubs.get(addr, 0)
                    if stub_val:  # non-zero stub: write it to the pre-mapped memory
                        try:
                            packed = (stub_val & ((1 << (size*8))-1)).to_bytes(size,"little")
                            mu.mem_write(addr, packed)
                        except Exception:
                            pass
                    ghidra_va = addr - self._rebase
                    global_reads_observed.append(GlobalRead(addr, size, stub_val, ghidra_va))
                    break

        # Build set of "safe" callee VAs: leaf functions in our calltree
        # All others get stubbed (return 0, skip execution)
        _safe_callees: set[int] = set()
        if self._fns:
            fn_data = self._fns.get(spec.fn_name, {})
            for callee_va_str in fn_data.get("called_vas", []):
                try:
                    callee_va = int(callee_va_str, 16)
                    callee_fn = self._fn_at(callee_va)
                    # Safe if: leaf (no callees) or PURE (no global writes)
                    if callee_fn and (
                        not callee_fn.get("named_callees") or
                        callee_fn.get("purity") == "PURE"
                    ):
                        _safe_callees.add(callee_va + self._rebase)  # runtime VA
                except Exception:
                    pass

        def _hook_instruction(mu, addr, size, _):
            """Detect CALL rel32 (0xE8) instructions; stub complex callees.

            Only handles 0xE8 (CALL rel32, always 5 bytes) — safe to skip.
            0xFF /2 (CALL r/m64) has variable length (2-7 bytes depending on
            ModRM/SIB/disp); skipping it without Capstone risks jumping to the
            middle of the instruction. Leave 0xFF calls to execute normally
            (they'll crash if they hit unmapped globals, which is fine —
            that crash tells us what global state is needed).
            """
            if size != 5:  # CALL rel32 is always exactly 5 bytes
                return
            try:
                opcode = bytes(mu.mem_read(addr, 1))[0]
                if opcode == 0xE8:
                    rel = int.from_bytes(bytes(mu.mem_read(addr+1, 4)), "little", signed=True)
                    target = addr + 5 + rel
                    # Only stub if target is a complex callee (not a leaf function)
                    target_gva = target - self._rebase
                    target_fn = self._fn_at(target_gva)
                    is_complex = (target_fn and
                                  len(target_fn.get("named_callees", [])) > 3)
                    if is_complex and target not in _safe_callees:
                        mu.reg_write(x86.UC_X86_REG_RAX, 0)
                        mu.reg_write(x86.UC_X86_REG_RIP, addr + 5)
            except Exception:
                pass

        mu.hook_add(uc.UC_HOOK_CODE, _hook_instruction)
        mu.hook_add(uc.UC_HOOK_BLOCK, _hook_block)
        # UC_HOOK_MEM_READ: fires on ALL reads (reliable, unlike UNMAPPED variant).
        # Filter inside callback to only track writable section reads (globals).
        mu.hook_add(uc.UC_HOOK_MEM_READ, _hook_mem_read)

        env.stopped[0] = False
        t0 = time.perf_counter()
        ok = False
        try:
            mu.emu_start(spec.va, spec.va + spec.size * 15,
                         timeout=2_000_000, count=max_instrs)
            ok = True
        except uc.UcError:
            pass
        elapsed = (time.perf_counter() - t0) * 1e6

        rax     = mu.reg_read(x86.UC_X86_REG_RAX)
        out_mem = bytes(mu.mem_read(OUTPUT_BASE, OUTPUT_SIZE))

        return CoverageResult(
            input_data=input_data,
            global_stubs=dict(global_stubs),
            output_data=out_mem,
            rax=rax,
            coverage=frozenset(coverage),
            global_reads=global_reads_observed,
            elapsed_us=elapsed,
            ok=ok or env.stopped[0],
        )


# ── Stub mutator ──────────────────────────────────────────────────────────────

# Stub values to try for each unknown global — covers common patterns:
# null check, non-null, small positive, large address, -1 (error), mode flags
_STUB_CANDIDATES = [0, 1, -1, 0xFF, 0x100, 0x1000, 0x10000,
                    0xDEADBEEF, 0x7FFFFFFF, 0x80000000]


def infer_required_globals(
    sim:        GlobalTrackingSim,
    spec:       SliceSpec,
    input_data: bytes | None = None,
    n_rounds:   int = 3,
    verbose:    bool = False,
) -> dict[int, int]:
    """
    Discover which global addresses affect code paths and what values unlock coverage.

    Algorithm:
    1. Run with all stubs = 0, record coverage baseline + all global reads
    2. For each global read address, try each stub candidate value
    3. If coverage CHANGES → that value unlocks new paths → record it
    4. Repeat with discovered state until no new coverage for n_rounds

    Returns: {runtime_address: best_stub_value} — the minimal state that
    maximises coverage, approximating what the init chain would have set.
    """
    if input_data is None:
        input_data = bytes([0x61] * 64)  # 'a' * 64

    best_stubs:  dict[int, int] = {}
    best_cov:    frozenset[int] = frozenset()
    no_new_rounds = 0

    for round_idx in range(20):  # max 20 rounds
        # Run with current best stubs
        result = sim._run_with_tracking(spec, input_data, best_stubs)
        new_blocks = result.coverage - best_cov
        if new_blocks:
            best_cov = result.coverage
            no_new_rounds = 0
        else:
            no_new_rounds += 1
            if no_new_rounds >= n_rounds:
                break

        if verbose:
            print(f"  [round {round_idx}] coverage={len(best_cov)} blocks, "
                  f"{len(result.global_reads)} global reads")

        # Try mutating each global read address
        improved = False
        for gr in result.global_reads:
            addr = gr.address
            current_val = best_stubs.get(addr, 0)
            for candidate in _STUB_CANDIDATES:
                if candidate == current_val:
                    continue
                trial_stubs = dict(best_stubs)
                trial_stubs[addr] = candidate
                trial = sim._run_with_tracking(spec, input_data, trial_stubs)
                if trial.coverage - best_cov:
                    # This value unlocks new coverage!
                    best_stubs[addr] = candidate
                    best_cov = trial.coverage | best_cov
                    improved = True
                    if verbose:
                        print(f"    addr={addr:#x} val={candidate} → "
                              f"+{len(trial.coverage - best_cov)} new blocks")
                    break

        if not improved:
            no_new_rounds += 1

    return best_stubs


# ── Z3 branch solver ──────────────────────────────────────────────────────────

def z3_solve_branch(condition_str: str, var_name: str = "x") -> list[int] | None:
    """
    Given a simple branch condition string from pseudocode, use Z3 to find
    satisfying + negating values.

    Examples:
        "x > 0x200" → [0x201, 0x200]  (satisfying, negating)
        "x != 0"    → [1, 0]
        "x & 1"     → [1, 0]

    Returns [true_case, false_case] or None if condition can't be parsed.
    """
    if not _HAS_Z3:
        return None
    try:
        x = z3.BitVec(var_name, 64)
        zero = z3.BitVecVal(0, 64)
        one  = z3.BitVecVal(1, 64)
        # Patterns matched against the condition string
        cond_map = [
            ("!= 0",  x != zero),
            ("== 0",  x == zero),
            ("> 0",   z3.UGT(x, zero)),
            (">= 0",  z3.UGE(x, zero)),
            ("< 0",   z3.ULT(x, zero)),
            ("<= 0",  z3.ULE(x, zero)),
            ("& 1",   (x & one) != zero),
        ]
        for pattern, formula in cond_map:
            if pattern in condition_str:
                results = []
                for f in [formula, z3.Not(formula)]:
                    s = z3.Solver()
                    s.add(f)
                    chk = s.check()
                    if str(chk) == "sat":
                        m = s.model()
                        v = m[x]
                        results.append(v.as_long() if v is not None else 0)
                    else:
                        results.append(None)
                return results
    except Exception as e:
        pass
    return None


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse, json
    ap = argparse.ArgumentParser(description="Global state inference for function simulation")
    ap.add_argument("--dll",       required=True)
    ap.add_argument("--calltree",  required=True)
    ap.add_argument("--func",      required=True, help="Function name or VA")
    ap.add_argument("--input-len", type=int, default=64, dest="input_len")
    ap.add_argument("--rounds",    type=int, default=3)
    ap.add_argument("--verbose",   action="store_true")
    args = ap.parse_args()

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sim = GlobalTrackingSim(args.dll, args.calltree)

    fn = sim._fns.get(args.func)
    if not fn:
        # Try VA lookup
        fn = next((f for f in sim._fns.values() if f["va"] == args.func), None)
    if not fn:
        print(f"Function not found: {args.func!r}")
        return

    spec = sim.classify(fn)
    print(f"Function: {spec.fn_name}  purity={spec.purity}  simulable={spec.simulable}")

    input_data = bytes([0x61] * args.input_len)

    print(f"\nPhase 1: Inferring required global state...")
    required_globals = infer_required_globals(
        sim, spec, input_data, n_rounds=args.rounds, verbose=args.verbose)

    if required_globals:
        print(f"\nRequired global state ({len(required_globals)} addresses):")
        for addr, val in sorted(required_globals.items()):
            gva = sim._to_ghidra(addr) if sim._in_dll(addr) else -1
            fn_at = sim._fn_at(gva)
            name = fn_at["name"] if fn_at else f"0x{addr:x}"
            print(f"  {addr:#x} (ghidra: {gva:#x} = {name}): stub_value={val}")
    else:
        print("  No global dependencies found (function may be self-contained)")

    print(f"\nPhase 2: Full simulation with discovered state...")
    # Use inferred globals to run a clean sweep
    from dynamic.slice_sim import IOProfile
    results = []
    rng = __import__("random").Random(42)
    for _ in range(32):
        data = bytes(rng.randrange(256) for _ in range(args.input_len))
        r = sim._run_with_tracking(spec, data, required_globals)
        if r.ok:
            results.append((r.input_data, r.output_data))

    print(f"  Successful probes: {len(results)}/32")
    if results:
        unique_outs = len(set(o[:8] for _, o in results))
        print(f"  Unique 8-byte outputs: {unique_outs}/{len(results)}")
        print(f"  Sample: in={results[0][0][:8].hex()}  out={results[0][1][:8].hex()}")


if __name__ == "__main__":
    main()
