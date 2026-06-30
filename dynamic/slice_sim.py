"""
dynamic/slice_sim.py - Unicorn-based slice simulation for behavioral fingerprinting.

Key insight (learned from FLARE-EMU, mandiant/flare-emu):
  You cannot copy function bytes to an arbitrary base address — x86-64 CALL/JMP
  instructions use PC-relative offsets computed from the original load VA.  Moving
  the bytes breaks every relative branch.

  The correct approach: map the DLL's PE sections into Unicorn at their REAL Ghidra
  VAs (image_base + section_vrva).  Since the DLL is already loaded in our process
  (via DLLExecutor), we read bytes directly from runtime memory (va + rebase) and
  write them into Unicorn at the emulated GhidraVA.  All relative addresses resolve
  correctly with zero fixup.

What this enables vs call_batch/call_buffer:
  - Pointer-argument functions   — map fake input/output at known addresses
  - Multi-pointer functions      — independent buffers for each pointer arg
  - Float/SIMD functions         — Unicorn handles XMM/YMM/FPU natively
  - Functions needing init       — skip setup, start at the computation loop

The core value: run thousands of controlled probes cheaply (Unicorn ~1µs/call vs
ctypes ~50µs), compute exact avalanche matrices, and compare I/O against Python
reference implementations — all without touching the real call stack.

Prior art:
  FLARE-EMU (mandiant)      - Unicorn + IDA, no systematic I/O sweeping
  Software Ethology/Tinbergen - academic, same idea, no public code
  Our contribution           - Ghidra integration + systematic probe sweeping
                               + algorithm matching layer
"""
from __future__ import annotations
import ctypes, os, re, sys, struct, time, random
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dynamic.execute import DLLExecutor
from pe_utils import PE

try:
    import unicorn as uc
    import unicorn.x86_const as x86
    _HAS_UNICORN = True
except ImportError:
    _HAS_UNICORN = False

# ── emulated address space layout ────────────────────────────────────────────
# DLL sections are mapped at their real Ghidra VAs (image_base + section_vrva).
# Synthetic regions live below 0x1000 to avoid collisions with real DLL space.

STACK_BASE  = 0x0000_0000_7FF0_0000
STACK_SIZE  = 0x0001_0000   # 64KB
INPUT_BASE  = 0x0000_0000_7FE0_0000
INPUT_SIZE  = 0x0001_0000   # 64KB — input buffer (RCX → here by default)
OUTPUT_BASE = 0x0000_0000_7FD0_0000
OUTPUT_SIZE = 0x0000_1000   # 4KB  — output buffer (R8 → here by default)

_NOISE_CALLEES = frozenset({
    "__security_check_cookie", "security_check_cookie",
    "__chkstk", "__GSHandlerCheck", "__GSHandlerCheck_SEH",
})

# ── register table (populated after import check) ────────────────────────────

def _reg(name: str) -> int:
    if not _HAS_UNICORN:
        return 0
    return getattr(x86, f"UC_X86_REG_{name.upper()}", 0)

_REGS = {n: _reg(n) for n in [
    "rax","rbx","rcx","rdx","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15",
    "rsp","rbp","rip",
]}


# ── data classes ──────────────────────────────────────────────────────────────

@dataclass
class SliceSpec:
    """
    Describes a simulable function slice.

    Purity tiers:
      PURE        no global reads/writes, no real external calls → exact I/O
      PURE_READS  reads globals (tables/constants) but no writes → stable I/O
      IMPURE      writes globals or calls non-noise external functions
    """
    va:          int
    size:        int        # instruction count from calltree
    fn_name:     str
    purity:      str        # "PURE" | "PURE_READS" | "IMPURE"
    has_ptr_in:  bool
    has_ptr_out: bool
    ext_callees: list[str] = field(default_factory=list)

    @property
    def simulable(self) -> bool:
        return self.purity != "IMPURE" and not self.ext_callees


@dataclass
class ProbeResult:
    input_data:  bytes
    output_data: bytes   # OUTPUT_BASE contents after emulation
    rax:         int
    elapsed_us:  float
    ok:          bool


@dataclass
class IOProfile:
    """
    Maximal I/O description from N probes.
    Primary evidence for algorithm identification.
    """
    fn_name:         str
    n_probes:        int
    n_ok:            int
    pairs:           list[tuple[bytes, bytes]]  # (input_bytes, output_bytes)
    rax_values:      list[int]
    elapsed_us_mean: float

    def match_reference(self, ref_fn, output_len: int = 8) -> float:
        """
        Score against a Python reference implementation.
        ref_fn(input_bytes: bytes) -> bytes
        Returns fraction of probes where emulated output == reference output.
        """
        if not self.pairs:
            return 0.0
        hits = sum(
            1 for inp, out in self.pairs
            if out[:output_len] == (ref_fn(inp) or b"")[:output_len]
        )
        return hits / len(self.pairs)

    def entropy_estimate(self, output_len: int = 8) -> float:
        """Fraction of unique output values — 1.0 = fully random (good hash)."""
        if not self.pairs:
            return 0.0
        outputs = [p[1][:output_len] for p in self.pairs if len(p[1]) >= output_len]
        return len(set(outputs)) / len(outputs) if outputs else 0.0


# ── PE section mapper ─────────────────────────────────────────────────────────

class _PEMapper:
    """
    Reads PE sections from the already-loaded DLL in our process and writes
    them into a Unicorn instance at their Ghidra VAs.

    Because the DLL is already mapped in our process at load_base, every byte
    at (image_base + rva) is readable at runtime address (load_base + rva).
    We map those bytes into Unicorn at the same Ghidra VA so all relative
    addresses in the code resolve correctly.
    """

    _PAGE = 0x1000

    def __init__(self, pe: PE, load_base: int):
        self.pe        = pe
        self.load_base = load_base
        self.rebase    = load_base - pe.image_base

    def _align(self, n: int) -> int:
        return (n + self._PAGE - 1) & ~(self._PAGE - 1)

    def map_sections(self, mu) -> None:
        """Map all PE sections into Unicorn at their Ghidra VAs."""
        for s in self.pe.sections:
            if s["vsize"] == 0:
                continue
            ghidra_va  = self.pe.image_base + s["vrva"]
            mapped_sz  = self._align(s["vsize"])
            runtime_va = self.load_base + s["vrva"]

            try:
                mu.mem_map(ghidra_va, mapped_sz)
            except uc.UcError:
                continue  # already mapped (overlap)

            try:
                data = bytes((ctypes.c_uint8 * s["vsize"]).from_address(runtime_va))
                mu.mem_write(ghidra_va, data)
            except (OSError, uc.UcError):
                pass  # write what we can


# ── cached Unicorn environment ────────────────────────────────────────────────

class _MuEnv:
    """
    A Unicorn instance with DLL sections pre-mapped.  Reused across probes —
    between runs we only rewrite the INPUT and OUTPUT regions, which is ~10µs
    vs ~14ms for a full rebuild.  The DLL code/data sections are immutable and
    never need rewriting.
    """

    def __init__(self, mapper: _PEMapper):
        self.mu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)
        mapper.map_sections(self.mu)

        self.mu.mem_map(STACK_BASE,  STACK_SIZE)
        self.mu.mem_map(INPUT_BASE,  INPUT_SIZE)
        self.mu.mem_map(OUTPUT_BASE, OUTPUT_SIZE)

        self.stack_top = STACK_BASE + STACK_SIZE - 0x100
        self.mu.mem_write(self.stack_top, struct.pack("<Q", 0xDEAD_C0DE_0000))

        # Register hooks ONCE — shared mutable stop flag reset per probe
        self.stopped = [False]

        def _hook_code(mu, addr, size, _):
            try:
                b = bytes(mu.mem_read(addr, min(size, 2)))
                if b and b[0] in (0xC3, 0xC2):
                    self.stopped[0] = True
                    mu.emu_stop()
            except uc.UcError:
                pass

        def _hook_mem_unmapped(mu, access, addr, size, value, _):
            return True

        def _hook_insn_invalid(mu, _):
            mu.emu_stop()
            return True

        self.mu.hook_add(uc.UC_HOOK_CODE, _hook_code)
        self.mu.hook_add(
            uc.UC_HOOK_MEM_READ_UNMAPPED |
            uc.UC_HOOK_MEM_WRITE_UNMAPPED |
            uc.UC_HOOK_MEM_FETCH_UNMAPPED,
            _hook_mem_unmapped)
        self.mu.hook_add(uc.UC_HOOK_INSN_INVALID, _hook_insn_invalid)

    def reset_io(self, input_data: bytes) -> None:
        """Overwrite input/output buffers for a fresh probe."""
        padded = (input_data + b"\x00" * INPUT_SIZE)[:INPUT_SIZE]
        self.mu.mem_write(INPUT_BASE,  padded)
        self.mu.mem_write(OUTPUT_BASE, b"\x00" * OUTPUT_SIZE)

    def set_registers(self, overrides: dict[str, int]) -> None:
        defaults = {
            "rcx": INPUT_BASE, "rdx": 0, "r8": OUTPUT_BASE, "r9": 0,
            "rsp": self.stack_top, "rbp": self.stack_top,
            "rax": 0, "rbx": 0, "rsi": 0, "rdi": 0,
        }
        defaults.update(overrides)
        for name, val in defaults.items():
            if name in _REGS:
                self.mu.reg_write(_REGS[name], val)


# ── main class ────────────────────────────────────────────────────────────────

class SliceSim:
    """
    Emulate functions from a loaded DLL using Unicorn with controlled I/O.

    Usage:
        sim = SliceSim(dll_path, calltree_path)
        spec = sim.classify(fn_entry)
        if spec.simulable:
            profile = sim.profile(spec, n_probes=512, input_len=64)
            score = profile.match_reference(my_algo_fn)
    """

    def __init__(self, dll_path: str, calltree_path: str | None = None):
        if not _HAS_UNICORN:
            raise ImportError("pip install unicorn")
        import json
        self.executor  = DLLExecutor(dll_path)
        self.pe        = PE(dll_path)
        self._mapper   = _PEMapper(self.pe, self.executor.load_base)
        self._env      = _MuEnv(self._mapper)   # built once, reused per probe
        self._fns: dict[str, dict] = {}
        if calltree_path:
            with open(calltree_path, encoding="utf-8") as f:
                d = json.load(f)
            self._fns = {fn["name"]: fn for fn in d["functions"]}

    # ── classification ────────────────────────────────────────────────────────

    def classify(self, fn: dict) -> SliceSpec:
        pcode = fn.get("pseudocode", "") or ""
        va    = int(fn["va"], 16) if isinstance(fn["va"], str) else fn["va"]

        has_global_writes = bool(re.search(r'DAT_[0-9a-fA-F]+\s*=', pcode))
        has_global_reads  = bool(re.search(r'\bDAT_[0-9a-fA-F]+', pcode))
        purity = ("IMPURE" if has_global_writes
                  else "PURE_READS" if has_global_reads
                  else "PURE")

        ext = [c for c in fn.get("named_callees", []) if c not in _NOISE_CALLEES]

        has_ptr_in  = bool(re.search(
            r'\*(longlong\s*\*\s*)?\(|puVar\w*\s*=.*param_|\*param_\d', pcode))
        has_ptr_out = bool(re.search(
            r'\*(p[bul]Var\w*|param_\d)\s*=', pcode))

        return SliceSpec(va=va, size=fn["size"], fn_name=fn["name"],
                         purity=purity, has_ptr_in=has_ptr_in,
                         has_ptr_out=has_ptr_out, ext_callees=ext)

    # ── Unicorn instance builder ──────────────────────────────────────────────

    # ── single emulated run ───────────────────────────────────────────────────

    def _run_once(
        self,
        spec:       SliceSpec,
        input_data: bytes,
        extra_regs: dict | None = None,
        max_instrs: int = 1_000_000,
    ) -> ProbeResult:
        """Emulate the function once using the cached Unicorn environment."""
        env = self._env
        env.reset_io(input_data)
        env.set_registers({"rcx": INPUT_BASE, "rdx": len(input_data),
                           "r8": OUTPUT_BASE, "r9": 0, **(extra_regs or {})})
        mu = env.mu

        env.stopped[0] = False   # reset shared stop flag

        t0 = time.perf_counter()
        ok = False
        try:
            mu.emu_start(spec.va, spec.va + spec.size * 15,
                         timeout=2_000_000, count=max_instrs)
            ok = True
        except uc.UcError:
            pass
        elapsed = (time.perf_counter() - t0) * 1e6

        rax     = mu.reg_read(_REGS["rax"])
        out_mem = bytes(mu.mem_read(OUTPUT_BASE, OUTPUT_SIZE))

        return ProbeResult(input_data, out_mem, rax, elapsed, ok or env.stopped[0])

    # ── probe sweeps ──────────────────────────────────────────────────────────

    def sweep_random(
        self,
        spec:      SliceSpec,
        n_probes:  int = 256,
        input_len: int = 64,
        seed:      int = 0,
    ) -> IOProfile:
        """Random probes — broad coverage of input space."""
        rng = random.Random(seed)
        pairs, raxes, times = [], [], []
        for _ in range(n_probes):
            data = bytes(rng.randrange(256) for _ in range(input_len))
            r = self._run_once(spec, data)
            if r.ok:
                pairs.append((r.input_data, r.output_data))
                raxes.append(r.rax)
                times.append(r.elapsed_us)
        return IOProfile(
            fn_name=spec.fn_name, n_probes=n_probes, n_ok=len(pairs),
            pairs=pairs, rax_values=raxes,
            elapsed_us_mean=sum(times) / len(times) if times else 0.0,
        )

    def sweep_bit_flips(
        self,
        spec:       SliceSpec,
        input_len:  int = 32,
        output_len: int = 8,
        base:       bytes | None = None,
    ) -> tuple[IOProfile, list[list[int]]]:
        """
        Exact avalanche matrix: for each input bit, which output bits flip?
        Returns (IOProfile, matrix[n_input_bits][output_len_bytes]).
        Produces 1 + input_len*8 probes total.
        """
        if base is None:
            base = bytes([0x61] * input_len)
        base_r    = self._run_once(spec, base)
        base_out  = base_r.output_data[:output_len]

        n_in   = input_len * 8
        matrix = [[0] * output_len for _ in range(n_in)]
        pairs  = [(base, base_r.output_data)]
        raxes  = [base_r.rax]
        times  = [base_r.elapsed_us]

        for i in range(n_in):
            flipped = bytearray(base)
            flipped[i >> 3] ^= 1 << (i & 7)
            r = self._run_once(spec, bytes(flipped))
            if r.ok:
                pairs.append((bytes(flipped), r.output_data))
                raxes.append(r.rax)
                times.append(r.elapsed_us)
                for j in range(output_len):
                    b_out = r.output_data[j] if j < len(r.output_data) else 0
                    b_base = base_out[j]      if j < len(base_out)      else 0
                    matrix[i][j] = b_out ^ b_base

        profile = IOProfile(
            fn_name=spec.fn_name, n_probes=n_in + 1, n_ok=len(pairs),
            pairs=pairs, rax_values=raxes,
            elapsed_us_mean=sum(times) / len(times) if times else 0.0,
        )
        return profile, matrix

    # ── reporting ─────────────────────────────────────────────────────────────

    def print_profile(self, profile: IOProfile, output_len: int = 8) -> None:
        print(f"\nSLICE PROFILE: {profile.fn_name}")
        print(f"  probes={profile.n_probes}  ok={profile.n_ok}"
              f"  avg={profile.elapsed_us_mean:.1f}µs/probe")
        if profile.pairs:
            entropy = profile.entropy_estimate(output_len)
            print(f"  output entropy: {entropy:.3f}  "
                  f"({'high — likely hash/crypto' if entropy > 0.95 else 'LOW'})")
            print(f"  sample I/O (first 4 probes):")
            for inp, out in profile.pairs[:4]:
                print(f"    in={inp[:8].hex()}...  out={out[:output_len].hex()}")
        rax_unique = len(set(profile.rax_values))
        if rax_unique > 1:
            print(f"  rax unique values: {rax_unique}/{len(profile.rax_values)}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Slice simulation — behavioral fingerprinting")
    ap.add_argument("--dll",        required=True)
    ap.add_argument("--calltree",   required=True)
    ap.add_argument("--func",       required=True)
    ap.add_argument("--probes",     type=int, default=64)
    ap.add_argument("--input-len",  type=int, default=64,  dest="input_len")
    ap.add_argument("--output-len", type=int, default=8,   dest="output_len")
    ap.add_argument("--bit-flip",   action="store_true",   dest="bit_flip")
    args = ap.parse_args()

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sim = SliceSim(args.dll, args.calltree)

    fn = sim._fns.get(args.func)
    if not fn:
        print(f"Function not found: {args.func!r}")
        print(f"Available (sample): {list(sim._fns)[:10]}")
        return

    spec = sim.classify(fn)
    print(f"SliceSpec: {spec.fn_name}")
    print(f"  purity={spec.purity}  ptr_in={spec.has_ptr_in}"
          f"  ptr_out={spec.has_ptr_out}  simulable={spec.simulable}")
    if spec.ext_callees:
        print(f"  blocked by external callees: {spec.ext_callees}")
        return

    if args.bit_flip:
        print(f"Running bit-flip avalanche sweep (input_len={args.input_len})...")
        profile, matrix = sim.sweep_bit_flips(
            spec, input_len=args.input_len, output_len=args.output_len)
        sim.print_profile(profile, args.output_len)
        if matrix:
            avg = sum(sum(row) for row in matrix) / (len(matrix) * args.output_len * 255.5)
            print(f"  avalanche_mean: {avg:.3f}  (ideal≈0.5 for a good hash)")
    else:
        print(f"Running {args.probes} random probes (input_len={args.input_len})...")
        profile = sim.sweep_random(spec, n_probes=args.probes, input_len=args.input_len)
        sim.print_profile(profile, args.output_len)


if __name__ == "__main__":
    main()
