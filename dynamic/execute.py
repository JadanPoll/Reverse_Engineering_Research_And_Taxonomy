"""
dynamic/execute.py — Safe DLL function executor: load, rebase, call by name or VA.

Architecture
------------
DLLExecutor loads a PE DLL, computes the rebase offset between Ghidra's preferred
base and the actual OS load address, then calls functions either by export name or
by Ghidra VA (for unnamed FUN_* internals).  call_batch() builds the CFUNCTYPE once
and iterates over a probe set, eliminating per-call setup overhead.

Crash containment
-----------------
OSError, ArgumentError, OverflowError, and TypeError are caught cleanly.  A genuine
access violation (STATUS_ACCESS_VIOLATION) bypasses Python exception handling and
crashes the interpreter.  For integer-only functions (hash, PRNG, CRC, codec) this is
rare in practice.  Pointer-argument functions should eventually use --isolated mode
(subprocess per call); that path is not yet implemented here.

CLI
---
    py re_toolkit/dynamic/execute.py --dll <path> --info
    py re_toolkit/dynamic/execute.py --dll <path> --func <export|0xVA> [--args n ...] [--ret i64]
    py re_toolkit/dynamic/execute.py --dll <path> --func 0x1800abcd0 --args 12345 0 --ret u64
"""
from __future__ import annotations
import ctypes, os, sys, time, json, argparse, multiprocessing
from dataclasses import dataclass, asdict

# make pe_utils importable regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pe_utils import PE


# ── Windows VirtualAlloc / guard-page setup ───────────────────────────────────
# Only initialised on Windows; call_buffer() raises NotImplementedError elsewhere.

_PAGE_SIZE   = 4096
_MEM_COMMIT  = 0x1000
_MEM_RESERVE = 0x2000
_MEM_RELEASE = 0x8000
_PAGE_RW     = 0x04
_PAGE_NA     = 0x01   # PAGE_NOACCESS

if sys.platform == "win32":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.VirtualAlloc.restype   = ctypes.c_void_p
    _k32.VirtualAlloc.argtypes  = [ctypes.c_void_p, ctypes.c_size_t,
                                    ctypes.c_ulong,  ctypes.c_ulong]
    _k32.VirtualFree.restype    = ctypes.c_bool
    _k32.VirtualFree.argtypes   = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
    _k32.VirtualProtect.restype  = ctypes.c_bool
    _k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                     ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
else:
    _k32 = None


def _alloc_guarded(size: int) -> tuple[int, int]:
    """
    Allocate `size` bytes followed by one PAGE_NOACCESS guard page.
    Returns (base_ptr, usable_size) where usable_size == page-aligned(size).
    Any write past usable_size triggers STATUS_ACCESS_VIOLATION → OSError.
    """
    if _k32 is None:
        raise NotImplementedError("call_buffer requires Windows (VirtualAlloc not available)")
    aligned = (size + _PAGE_SIZE - 1) & ~(_PAGE_SIZE - 1)
    total   = aligned + _PAGE_SIZE
    base    = _k32.VirtualAlloc(None, total, _MEM_COMMIT | _MEM_RESERVE, _PAGE_RW)
    if not base:
        raise MemoryError(f"VirtualAlloc({total}) failed: err={ctypes.get_last_error()}")
    old = ctypes.c_ulong(0)
    if not _k32.VirtualProtect(base + aligned, _PAGE_SIZE, _PAGE_NA, ctypes.byref(old)):
        _k32.VirtualFree(base, 0, _MEM_RELEASE)
        raise MemoryError(f"VirtualProtect guard failed: err={ctypes.get_last_error()}")
    return base, aligned


def _free_guarded(base: int) -> None:
    if _k32 is not None:
        _k32.VirtualFree(base, 0, _MEM_RELEASE)


_C_INT64 = ctypes.c_int64

_RET_TYPES: dict[str, type] = {
    "i64": ctypes.c_int64,
    "u64": ctypes.c_uint64,
    "i32": ctypes.c_int32,
    "u32": ctypes.c_uint32,
    "i16": ctypes.c_int16,
    "u16": ctypes.c_uint16,
    "i8":  ctypes.c_int8,
    "u8":  ctypes.c_uint8,
}


@dataclass
class BufferResult:
    """
    Result of call_buffer() — a function called with a heap-allocated input buffer.

    output_bytes : contents of the buffer after the call (or None on hard error).
                   Hex-encode for JSON: result.output_bytes.hex()
    overflow_detected : True when the call raised OSError with access-violation
                        signature, meaning the function wrote past the guard page.
    """
    func_id:           str
    retval:            int | None
    error:             str | None
    elapsed_us:        float
    actual_addr:       int
    output_bytes:      bytes | None
    overflow_detected: bool

    def to_dict(self) -> dict:
        return {
            "func_id":          self.func_id,
            "retval":           self.retval,
            "retval_hex":       hex(self.retval) if self.retval is not None else None,
            "error":            self.error,
            "elapsed_us":       round(self.elapsed_us, 2),
            "actual_addr":      hex(self.actual_addr) if self.actual_addr else None,
            "output_bytes":     self.output_bytes.hex() if self.output_bytes else None,
            "output_len":       len(self.output_bytes) if self.output_bytes else 0,
            "overflow_detected": self.overflow_detected,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class ExecuteResult:
    func_id:     str          # export name or "FUN_xxxxxxxx"
    args:        list         # arguments passed
    retval:      int | None   # integer return value; None on error
    error:       str | None   # None on success, exception description on failure
    elapsed_us:  float        # wall-clock microseconds for the call itself
    actual_addr: int          # actual load address (0 for named exports)


def _isolated_buffer_worker(
    dll_path: str,
    func,
    buf_size: int,
    fill_bytes: bytes,
    extra_args: list,
    arg_type_names: list[str],
    ret_type_name: str,
    queue,          # multiprocessing.Queue
) -> None:
    """
    Module-level worker for call_buffer(isolated=True).
    Runs inside a subprocess — crashes here kill only this process.
    Reconstructs DLLExecutor, calls the function with the supplied fill_bytes,
    and puts a BufferResult into `queue`.
    """
    _type_map = {
        "c_int64": ctypes.c_int64,  "c_uint64": ctypes.c_uint64,
        "c_int32": ctypes.c_int32,  "c_uint32": ctypes.c_uint32,
        "c_int16": ctypes.c_int16,  "c_uint16": ctypes.c_uint16,
        "c_int8":  ctypes.c_int8,   "c_uint8":  ctypes.c_uint8,
        "c_void_p": ctypes.c_void_p, "c_char_p": ctypes.c_char_p,
    }
    func_id = f"FUN_{func:08x}" if isinstance(func, int) else func
    try:
        ex       = DLLExecutor(dll_path)
        atypes   = [_type_map.get(n, ctypes.c_int64) for n in arg_type_names] or None
        rtype    = _type_map.get(ret_type_name, ctypes.c_int64)

        def _fill(addr, size):
            ctypes.memmove(addr, fill_bytes[:size], min(len(fill_bytes), size))

        result = ex._call_buffer_direct(func, buf_size, _fill, None,
                                        extra_args, atypes, rtype)
        queue.put(result)
    except Exception as exc:
        queue.put(BufferResult(func_id, None, f"worker: {exc}", 0.0, 0, None, False))


class DLLExecutor:
    """
    Load a PE DLL and call its functions by export name or by Ghidra VA.

    On Windows, ctypes.CDLL._handle is the HMODULE returned by LoadLibraryEx,
    which equals the actual load base.  rebase = load_base - pe.image_base; add
    it to any Ghidra VA to get the address at runtime.
    """

    def __init__(self, dll_path: str):
        self.dll_path   = os.path.abspath(dll_path)
        self.pe         = PE(self.dll_path)
        self._dll       = ctypes.CDLL(self.dll_path)
        self.load_base: int = self._dll._handle           # HMODULE == actual base
        self.rebase:    int = self.load_base - self.pe.image_base

    # ── single-call API ──────────────────────────────────────────────────────

    def call_export(
        self,
        name: str,
        args: list,
        arg_types: list | None = None,
        ret_type = None,
    ) -> ExecuteResult:
        """Call an exported function by name."""
        arg_types = arg_types or [_C_INT64] * len(args)
        ret_type  = ret_type  or _C_INT64

        fn = getattr(self._dll, name, None)
        if fn is None:
            return ExecuteResult(name, list(args), None,
                                 f"export {name!r} not found", 0.0, 0)
        fn.argtypes = arg_types
        fn.restype  = ret_type
        return self._timed_call(name, fn, args, 0)

    def call_va(
        self,
        ghidra_va: int,
        args: list,
        arg_types: list | None = None,
        ret_type = None,
    ) -> ExecuteResult:
        """Call an internal FUN_* function by its Ghidra VA (auto-rebased)."""
        arg_types = arg_types or [_C_INT64] * len(args)
        ret_type  = ret_type  or _C_INT64

        actual  = ghidra_va + self.rebase
        func_id = f"FUN_{ghidra_va:08x}"
        try:
            fn = ctypes.CFUNCTYPE(ret_type, *arg_types)(actual)
        except Exception as e:
            return ExecuteResult(func_id, list(args), None,
                                 f"CFUNCTYPE: {e}", 0.0, actual)
        return self._timed_call(func_id, fn, args, actual)

    # ── batch API (efficient for fingerprinting) ─────────────────────────────

    def call_batch(
        self,
        func: int | str,
        probe_set: list[list],
        arg_types: list | None = None,
        ret_type = None,
    ) -> list[ExecuteResult]:
        """
        Call the same function with many probe inputs.

        Builds the CFUNCTYPE / export binding once, then iterates over
        probe_set.  Use this from fingerprint.py to avoid per-call overhead.

        Parameters
        ----------
        func : int | str
            Ghidra VA (int) for FUN_* internals, or export name (str).
        probe_set : list of lists
            Each inner list is one set of arguments.
        """
        if not probe_set:
            return []

        n_args    = len(probe_set[0])
        arg_types = arg_types or [_C_INT64] * n_args
        ret_type  = ret_type  or _C_INT64

        if isinstance(func, int):
            ghidra_va = func
            actual    = ghidra_va + self.rebase
            func_id   = f"FUN_{ghidra_va:08x}"
            try:
                fn = ctypes.CFUNCTYPE(ret_type, *arg_types)(actual)
            except Exception as e:
                err = f"CFUNCTYPE: {e}"
                return [ExecuteResult(func_id, list(p), None, err, 0.0, actual)
                        for p in probe_set]
        else:
            func_id = func
            actual  = 0
            fn = getattr(self._dll, func, None)
            if fn is None:
                err = f"export {func!r} not found"
                return [ExecuteResult(func_id, list(p), None, err, 0.0, 0)
                        for p in probe_set]
            fn.argtypes = arg_types
            fn.restype  = ret_type

        return [self._timed_call(func_id, fn, probe, actual) for probe in probe_set]

    # ── buffer API (pointer-argument functions) ──────────────────────────────

    def call_buffer(
        self,
        func:        int | str,
        buf_size:    int,
        fill_fn,                         # fill_fn(buf_addr: int, buf_size: int)
        read_fn      = None,             # read_fn(buf_addr: int, buf_size: int) -> bytes
                                         # default: read all buf_size bytes
        extra_args:  list | None = None, # scalar args appended after the buffer pointer
        arg_types:   list | None = None, # ctypes for [buf_ptr, *extra_args]; default void_p + int64s
        ret_type                 = None, # default c_int64
        isolated:    bool        = False,# True → run in subprocess (crash-safe)
    ) -> BufferResult:
        """
        Call `func` with a heap-allocated, guard-paged buffer as its first argument.

        The buffer layout:
          [0 .. buf_size)   ← fill_fn writes here; func reads/writes here
          [buf_size .. +4096) ← PAGE_NOACCESS guard — any write triggers OSError

        Parameters
        ----------
        fill_fn   : called before the function; writes probe data into the buffer.
        read_fn   : called after the function; extracts output bytes.
                    If None, all buf_size bytes are read back verbatim.
        extra_args: additional scalar arguments passed after the buffer pointer
                    (e.g. a size argument: call_buffer(..., extra_args=[buf_size]))
        isolated  : run in a subprocess via multiprocessing.Process.
                    Crashes (access violation, stack overflow) kill the worker,
                    not the analyzer process.  ~10s timeout.
        """
        if isolated:
            return self._call_buffer_isolated(func, buf_size, fill_fn, read_fn,
                                              extra_args, arg_types, ret_type)
        return self._call_buffer_direct(func, buf_size, fill_fn, read_fn,
                                        extra_args, arg_types, ret_type)

    def _call_buffer_direct(
        self, func, buf_size, fill_fn, read_fn, extra_args, arg_types, ret_type
    ) -> BufferResult:
        extra_args = extra_args or []
        ret_type   = ret_type   or _C_INT64
        if arg_types is None:
            arg_types = [ctypes.c_void_p] + [_C_INT64] * len(extra_args)

        # Resolve function once before allocating the buffer
        if isinstance(func, int):
            actual  = func + self.rebase
            func_id = f"FUN_{func:08x}"
            try:
                fn = ctypes.CFUNCTYPE(ret_type, *arg_types)(actual)
            except Exception as e:
                return BufferResult(func_id, None, f"CFUNCTYPE: {e}", 0.0, actual, None, False)
        else:
            func_id = func
            actual  = 0
            fn = getattr(self._dll, func, None)
            if fn is None:
                return BufferResult(func_id, None, f"export {func!r} not found",
                                    0.0, 0, None, False)
            fn.argtypes = arg_types
            fn.restype  = ret_type

        try:
            buf_base, buf_cap = _alloc_guarded(buf_size)
        except (MemoryError, NotImplementedError) as e:
            return BufferResult(func_id, None, str(e), 0.0, actual, None, False)

        try:
            fill_fn(buf_base, buf_size)
            call_args = [buf_base] + list(extra_args)
            t0 = time.perf_counter()
            try:
                retval  = fn(*call_args)
                elapsed = (time.perf_counter() - t0) * 1e6
                overflow = False
                error    = None
            except OSError as e:
                elapsed  = (time.perf_counter() - t0) * 1e6
                overflow = ("0xc0000005" in str(e).lower() or
                            "access violation" in str(e).lower())
                error    = f"OSError: {e}"
                retval   = None
            except Exception as e:
                elapsed  = (time.perf_counter() - t0) * 1e6
                overflow = False
                error    = f"{type(e).__name__}: {e}"
                retval   = None

            # Read back buffer regardless of error (partial output still useful)
            try:
                if read_fn is not None:
                    output = read_fn(buf_base, buf_size)
                else:
                    output = bytes((ctypes.c_uint8 * buf_size).from_address(buf_base))
            except Exception:
                output = None

            return BufferResult(
                func_id          = func_id,
                retval           = int(retval) if retval is not None else None,
                error            = error,
                elapsed_us       = elapsed,
                actual_addr      = actual,
                output_bytes     = output,
                overflow_detected = overflow,
            )
        finally:
            _free_guarded(buf_base)

    def call_dual_buffer(
        self,
        func:       int | str,
        input_data: bytes,
        output_size: int,
        scalar_args: list | None = None,
        arg_layout:  str = "in_len_out_tail",
        ret_type    = None,
    ) -> BufferResult:
        """
        Call a function that takes BOTH an input pointer and a separate output pointer.

        arg_layout controls argument order:
          "in_len_out_tail"  (default) → fn(in_ptr, len, out_ptr, *scalar_args)
          "in_out_len_tail"            → fn(in_ptr, out_ptr, len, *scalar_args)
          "in_out_tail"                → fn(in_ptr, out_ptr, *scalar_args)

        Allocates guard-paged input and output buffers; reads output_size bytes
        after the call and returns them in BufferResult.output_bytes.

        Example — MetroHash64::Hash(key_ptr, len, out_ptr, seed):
            result = executor.call_dual_buffer(
                func       = 0x180042014,
                input_data = b"hello world",
                output_size = 8,
                scalar_args = [0],           # seed=0
                arg_layout  = "in_len_out_tail",
            )
            hash_bytes = result.output_bytes[:8]
        """
        scalar_args = scalar_args or []
        ret_type    = ret_type or _C_INT64
        func_id     = f"FUN_{func:08x}" if isinstance(func, int) else func

        in_size  = max(len(input_data), 1)
        out_size = max(output_size, 1)

        in_base,  in_usable  = _alloc_guarded(in_size)
        out_base, out_usable = _alloc_guarded(out_size)
        try:
            # Fill input
            ctypes.memmove(in_base, input_data, min(len(input_data), in_usable))

            # Build arg list
            if arg_layout == "in_len_out_tail":
                all_args = [in_base, len(input_data), out_base] + scalar_args
                all_types = ([ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
                             + [ctypes.c_uint64] * len(scalar_args))
            elif arg_layout == "in_out_len_tail":
                all_args = [in_base, out_base, len(input_data)] + scalar_args
                all_types = ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
                             + [ctypes.c_uint64] * len(scalar_args))
            elif arg_layout == "in_out_tail":
                all_args = [in_base, out_base] + scalar_args
                all_types = ([ctypes.c_void_p, ctypes.c_void_p]
                             + [ctypes.c_uint64] * len(scalar_args))
            else:
                raise ValueError(f"Unknown arg_layout: {arg_layout!r}")

            # Resolve function
            if isinstance(func, int):
                actual = func + self.rebase
                fn = ctypes.CFUNCTYPE(ret_type, *all_types)(actual)
            else:
                fn = getattr(self._dll, func, None)
                if fn is None:
                    return BufferResult(func_id, None, f"export {func!r} not found",
                                        0.0, 0, None, False)
                fn.argtypes = all_types
                fn.restype  = ret_type
                actual = 0

            error, retval, overflow = None, None, False
            t0 = time.perf_counter()
            try:
                retval = int(fn(*all_args))
            except OSError as e:
                if "access violation" in str(e).lower():
                    overflow = True
                    error = f"ACCESS_VIOLATION: {e}"
                else:
                    error = str(e)
            except Exception as e:
                error = str(e)
            elapsed = (time.perf_counter() - t0) * 1e6

            output = bytes((ctypes.c_uint8 * output_size).from_address(out_base))

            return BufferResult(
                func_id=func_id, retval=retval, error=error,
                elapsed_us=elapsed, actual_addr=actual,
                output_bytes=output, overflow_detected=overflow,
            )
        finally:
            _free_guarded(in_base)
            _free_guarded(out_base)

    def _call_buffer_isolated(
        self, func, buf_size, fill_fn, read_fn, extra_args, arg_types, ret_type
    ) -> BufferResult:
        """Run call_buffer in a subprocess so crashes don't kill the analyzer."""
        func_id = f"FUN_{func:08x}" if isinstance(func, int) else func

        # Materialise fill_fn output to plain bytes so it survives pickling
        local_buf = (ctypes.c_uint8 * buf_size)()
        try:
            fill_fn(ctypes.addressof(local_buf), buf_size)
        except Exception as e:
            return BufferResult(func_id, None, f"fill_fn: {e}", 0.0, 0, None, False)
        fill_bytes = bytes(local_buf)

        extra_args     = extra_args or []
        ret_type       = ret_type   or _C_INT64
        if arg_types is None:
            arg_types = [ctypes.c_void_p] + [_C_INT64] * len(extra_args)

        arg_type_names = [getattr(t, '__name__', 'c_int64') for t in arg_types]
        ret_type_name  = getattr(ret_type, '__name__', 'c_int64')

        q = multiprocessing.Queue()
        p = multiprocessing.Process(
            target  = _isolated_buffer_worker,
            args    = (self.dll_path, func, buf_size, fill_bytes, extra_args,
                       arg_type_names, ret_type_name, q),
            daemon  = True,
        )
        p.start()
        p.join(timeout=10)

        if p.is_alive():
            p.terminate()
            p.join(timeout=2)
            return BufferResult(func_id, None, "timeout (10s)", 0.0, 0, None, False)

        if p.exitcode != 0:
            return BufferResult(func_id, None,
                                f"worker crashed (exit {p.exitcode})",
                                0.0, 0, None, p.exitcode == -11 or p.exitcode == 0xC0000005)
        try:
            return q.get_nowait()
        except Exception:
            return BufferResult(func_id, None, "no result from worker", 0.0, 0, None, False)

    # ── diagnostics ──────────────────────────────────────────────────────────

    def info(self) -> dict:
        return {
            "dll_path":      self.dll_path,
            "image_base":    hex(self.pe.image_base),
            "load_base":     hex(self.load_base),
            "rebase_offset": hex(self.rebase),
            "bits":          self.pe.bits,
            "sections":      len(self.pe.sections),
        }

    # ── internals ────────────────────────────────────────────────────────────

    def _timed_call(
        self, func_id: str, fn, args: list, actual_addr: int
    ) -> ExecuteResult:
        t0 = time.perf_counter()
        try:
            retval  = fn(*args)
            elapsed = (time.perf_counter() - t0) * 1e6
            return ExecuteResult(func_id, list(args), int(retval), None, elapsed, actual_addr)
        except (OSError, ctypes.ArgumentError, OverflowError, ValueError, TypeError) as e:
            elapsed = (time.perf_counter() - t0) * 1e6
            return ExecuteResult(func_id, list(args), None,
                                 f"{type(e).__name__}: {e}", elapsed, actual_addr)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _result_to_json(r: ExecuteResult) -> dict:
    return {
        "func_id":     r.func_id,
        "args":        r.args,
        "retval":      r.retval,
        "retval_hex":  hex(r.retval) if r.retval is not None else None,
        "error":       r.error,
        "elapsed_us":  round(r.elapsed_us, 2),
        "actual_addr": hex(r.actual_addr) if r.actual_addr else None,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Execute a DLL function and print the result as JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--dll",  required=True, help="Path to the DLL")
    ap.add_argument("--func", help="Export name or Ghidra VA (0x...)")
    ap.add_argument("--args", nargs="*", default=[],
                    help="Arguments: decimal or 0x hex integers")
    ap.add_argument("--ret",  default="i64", choices=list(_RET_TYPES),
                    help="Return type (default: i64)")
    ap.add_argument("--info", action="store_true",
                    help="Print rebase/load info and exit")
    opts = ap.parse_args()

    ex = DLLExecutor(opts.dll)

    if opts.info:
        print(json.dumps(ex.info(), indent=2))
        sys.exit(0)

    if not opts.func:
        ap.error("--func is required unless --info is used")

    ret_type   = _RET_TYPES[opts.ret]
    parsed_args = [int(a, 0) for a in opts.args]

    if opts.func.startswith("0x") or opts.func.startswith("0X"):
        result = ex.call_va(int(opts.func, 16), parsed_args, ret_type=ret_type)
    else:
        result = ex.call_export(opts.func, parsed_args, ret_type=ret_type)

    print(json.dumps(_result_to_json(result), indent=2))
