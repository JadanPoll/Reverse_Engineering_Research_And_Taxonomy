# @runtime PyGhidra
# @title Dump call tree + pseudocode as JSON for LLM naming
# @description
#   Starting from seed virtual addresses (or xrefs to known string addresses),
#   walks the call graph to depth N, decompiles every function, and writes a
#   JSON file ready for llm_name_functions.py.
#
#   Seeds and output path are read from ground_truth.py (in the same folder).
#   This script contains NO target-specific constants — edit ground_truth.py.
#
# Usage (pyghidra headless):
#   py -3.13 hss_toolkit/ghidra_run.py --calltree
#   or call main() directly from a running Ghidra session
#
# Config overrides (env vars take precedence over ground_truth.py):
#   GHIDRA_SEEDS  = comma-separated hex VAs of seed functions
#   GHIDRA_DEPTH  = integer max depth (default 4)
#   GHIDRA_OUT    = output JSON path

import os, json, sys, struct, collections, re as _re
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task       import TaskMonitor
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.symbol import SourceType

# ── Load target config from ground_truth.py ───────────────────────────────────
# ground_truth.py is the ONLY file with target-specific constants.
# Import is best-effort: if it fails, env vars or manual editing are the fallback.

_here = os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else os.getcwd()
if _here not in sys.path:
    sys.path.insert(0, _here)

try:
    from ground_truth import KNOWN_VAS, KNOWN_STRINGS, CALLTREE_JSON
    FUNCTION_SEEDS_DEFAULT = list(KNOWN_VAS.values())
    STRING_SEEDS_DEFAULT   = list(KNOWN_STRINGS.keys())
    OUT_DEFAULT            = CALLTREE_JSON
    print("Config: loaded seeds from ground_truth.py")
except Exception as _e:
    # Fallback: no seeds. Set GHIDRA_SEEDS env var or edit ground_truth.py.
    print(f"Config: ground_truth.py not loaded ({_e}) -- set GHIDRA_SEEDS env var")
    FUNCTION_SEEDS_DEFAULT = []
    STRING_SEEDS_DEFAULT   = []
    OUT_DEFAULT = os.path.join(_here, "ghidra_calltree.json")

MAX_DEPTH_DEFAULT = 4

# ── Seed strategy ─────────────────────────────────────────────────────────────
#
# FUNCTION_SEEDS: direct function entry-point VAs (from ground_truth.KNOWN_VAS).
#   Always reliable. Tried FIRST.
#
# STRING_SEEDS: data-section VAs of string literals (from ground_truth.KNOWN_STRINGS).
#   Resolved via Ghidra xref manager. Unreliable in headless mode (x86 Constant
#   Reference Analyzer often skips data refs). Named floor: XREF_HEADLESS_GAP.
#
# NativeAOT frozen string layout:
#   [va+0x00] MethodTable ptr (8 bytes)
#   [va+0x08] string length   (4 bytes)
#   [va+0x0c] padding         (4 bytes)
#   [va+0x10] char array      (UTF-16LE)
# Our scanner returns char-array VA (object+0x10); get_string_refs() probes
# multiple offsets to find where Ghidra recorded the xref.

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_addr(va):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(va)

def ensure_function(addr):
    fm = currentProgram.getFunctionManager()
    func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
    if func:
        return func
    tx = currentProgram.startTransaction("disasm+func")
    try:
        DisassembleCommand(addr, None, True).applyTo(currentProgram, monitor)
        CreateFunctionCmd(addr).applyTo(currentProgram, monitor)
    finally:
        currentProgram.endTransaction(tx, True)
    return fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)

_decompiler = None

def get_decompiler():
    global _decompiler
    if _decompiler is None:
        _decompiler = DecompInterface()
        opts = DecompileOptions()
        _decompiler.setOptions(opts)
        _decompiler.setSimplificationStyle("decompile")
        _decompiler.openProgram(currentProgram)
    return _decompiler

def decompile(func, timeout=60):
    try:
        res = get_decompiler().decompileFunction(func, timeout, monitor)
        if res and res.decompileCompleted():
            d = res.getDecompiledFunction()
            return d.getC() if d else None
        msg = res.getErrorMessage() if res else "timeout"
        return f"/* FAILED [{msg}] FLOOR:DECOMPILER_FAILED */"
    except Exception as e:
        return f"/* EXCEPTION [{e}] FLOOR:DECOMPILER_FAILED */"


def read_cstring(addr, max_len=64):
    """Read a NUL-terminated printable-ASCII string from program memory."""
    mem = currentProgram.getMemory()
    result = []
    cur = addr
    try:
        for _ in range(max_len):
            b = mem.getByte(cur) & 0xFF
            if b == 0:
                return ''.join(result)
            if b < 0x20 or b > 0x7e:
                return None   # non-printable: not a C-string
            result.append(chr(b))
            cur = cur.add(1)
    except Exception:
        pass
    return ''.join(result) if result else None


def resolve_pointer_entries(buf):
    """
    Interpret `buf` (list of ints) as a table of 8-byte LE pointers.
    For each valid pointer within program memory, classify as:
      - "function": there is a function entry point at that exact VA
      - "string": points to readable NUL-terminated ASCII
      - "data": valid VA but neither of the above
    Stops at the first zero entry or non-addressable VA (treats those as table end).
    Returns list of {va, type, name/value} dicts.
    """
    mem = currentProgram.getMemory()
    fm  = currentProgram.getFunctionManager()
    as_ = currentProgram.getAddressFactory().getDefaultAddressSpace()
    entries = []

    n_ptrs = len(buf) // 8
    for i in range(n_ptrs):
        chunk = buf[i*8 : i*8+8]
        if len(chunk) < 8:
            break
        va = struct.unpack_from('<Q', bytes(chunk))[0]
        if va == 0:
            break   # null terminator
        try:
            addr = as_.getAddress(va)
        except Exception:
            break
        if not mem.contains(addr):
            break   # past end of loaded image
        func = fm.getFunctionAt(addr)
        if func and func.getEntryPoint().getOffset() == va:
            entries.append({"va": f"0x{va:x}", "type": "function", "name": str(func.getName())})
        else:
            s = read_cstring(addr)
            if s is not None:
                entries.append({"va": f"0x{va:x}", "type": "string", "value": s})
            else:
                entries.append({"va": f"0x{va:x}", "type": "data", "value": "(non-printable)"})

    return entries


# ── GAP fixes ─────────────────────────────────────────────────────────────────

def extract_global_arrays(pcode, n_bytes=64):
    """
    GAP-1 fix: RDATA_NOT_SURFACED.
    Scan pseudocode for global array accesses (NAME[...] where NAME is an
    all-caps identifier visible in the symbol table). For each found global,
    read the first n_bytes from program memory and return them alongside the VA.

    Also runs resolve_pointer_entries() on those bytes:
    GAP-3 fix: RDATA_POINTER_TABLE_NOT_DEREFERENCED — if the array contains
    valid-VA 8-byte LE pointers, dereference each to its string value.
    GAP-4 fix: INDIRECT_CALL_TARGETS_UNRESOLVED — if the pointers point to
    function entry points, record the function names so they can be auto-seeded.

    Returns {name: {"va": "0x...", "first_bytes": "hex...", "n_bytes": N,
                    "pointer_entries": [{va, type, name/value}, ...]}}
    """
    results = {}
    sym_table = currentProgram.getSymbolTable()
    mem       = currentProgram.getMemory()

    for name in set(_re.findall(r'\b([A-Z_][A-Z0-9_]{2,})\s*\[', pcode)):
        syms = list(sym_table.getSymbols(name))
        if not syms:
            continue
        addr = syms[0].getAddress()
        # mem.getBytes(addr, bytearray) does not write back through JPype —
        # read byte-by-byte with getByte() which returns a Java signed byte.
        buf = []
        cur = addr
        try:
            for _ in range(n_bytes):
                buf.append(mem.getByte(cur) & 0xFF)
                cur = cur.add(1)
        except Exception:
            pass
        if not buf:
            continue
        entry = {
            "va":          f"0x{addr.getOffset():x}",
            "first_bytes": bytes(buf).hex(),
            "n_bytes":     len(buf),
        }
        ptr_entries = resolve_pointer_entries(buf)
        if ptr_entries:
            entry["pointer_entries"] = ptr_entries
        results[name] = entry
    return results


def extract_rdata_refs(func, n_bytes=64):
    """
    GAP fix: GLOBAL_ARRAYS_NOT_SURFACED_FROM_EXPORTS_ONLY.
    Follow Ghidra data references from `func` into .rdata/.rodata and extract
    bytes from each referenced address.  Complements extract_global_arrays(),
    which only catches ALL_CAPS symbol names that appear in pseudocode.

    This catches lookup tables (base64 alphabet, CRC tables, codec maps) that
    are referenced via plain pointer loads and never get a Ghidra symbol name,
    or whose symbol name does not match the ALL_CAPS[...] regex.

    Returns same dict format as extract_global_arrays():
      {name: {"va": "0x...", "first_bytes": "hex...", "n_bytes": N,
              "pointer_entries"?: [...]}}
    """
    ref_mgr = currentProgram.getReferenceManager()
    mem     = currentProgram.getMemory()
    sym_tbl = currentProgram.getSymbolTable()

    # Read-only data sections (.rdata/.rodata): constants, lookup tables, string tables.
    rdata_blocks = [b for b in mem.getBlocks()
                    if b.getName() in ('.rdata', '.rodata')
                    and b.isInitialized() and not b.isWrite()]

    # Writable data sections (.data): function pointer dispatch tables live here because
    # the loader patches them for ASLR relocation. Include ONLY if resolve_pointer_entries
    # confirms the target contains valid function pointers — avoids noise from plain data.
    data_blocks = [b for b in mem.getBlocks()
                   if b.getName() in ('.data', '.data1')
                   and b.isInitialized() and b.isWrite()]

    all_blocks = rdata_blocks + data_blocks
    if not all_blocks:
        return {}

    results = {}
    seen    = set()
    body    = func.getBody()

    body_max = body.getMaxAddress()
    ref_iter = ref_mgr.getReferenceIterator(body.getMinAddress())
    for ref in ref_iter:
        if ref.getFromAddress().compareTo(body_max) > 0:
            break
        if not ref.getReferenceType().isData():
            continue
        target = ref.getToAddress()
        in_rdata = any(b.contains(target) for b in rdata_blocks)
        in_data  = any(b.contains(target) for b in data_blocks)
        if not in_rdata and not in_data:
            continue
        off = target.getOffset()
        if off in seen:
            continue
        seen.add(off)

        buf = []
        cur = target
        try:
            for _ in range(n_bytes):
                buf.append(mem.getByte(cur) & 0xFF)
                cur = cur.add(1)
        except Exception:
            pass
        if not buf:
            continue

        ptr_entries = resolve_pointer_entries(buf)

        # For .data references: only include if they contain function pointers.
        # Plain data in .data (globals, counters, buffers) is not useful here.
        if in_data and not any(e["type"] == "function" for e in ptr_entries):
            continue

        syms = list(sym_tbl.getSymbols(target))
        name = str(syms[0].getName()) if syms else f"rdata_{off:x}"
        if name in results:
            continue   # already captured by extract_global_arrays()

        entry = {
            "va":          f"0x{off:x}",
            "first_bytes": bytes(buf).hex(),
            "n_bytes":     len(buf),
        }
        if ptr_entries:
            entry["pointer_entries"] = ptr_entries
        results[name] = entry

    return results


def extract_eh_callsites(func):
    """
    GAP fix: EH_CLEANUP_NOT_SURFACED.
    Find EH call-site → landing-pad mappings for `func`.

    Strategy 1 (preferred): Ghidra's RegionDescriptor/LSDATable API.
      RegionDescriptor wraps the function range + its parsed LSDA table.
      Each LSDACallSiteRecord maps a protected code range to a landing pad VA.

    Strategy 2 (fallback): scan DATA cross-references from the
      .gcc_except_table section into the function body. Ghidra may have
      created these during its own EH analysis even if the API approach fails.

    Returns list of (protected_range_str, landing_pad_va_int) tuples.
    """
    results = []

    # Strategy 1: Ghidra LSDATable API
    try:
        from ghidra.app.plugin.exceptionhandlers.gcc import RegionDescriptor
        region = RegionDescriptor(func.getEntryPoint(), func.getBody())
        lsda   = region.getLSDATable()
        if lsda:
            cst = lsda.getCallSiteTable()
            if cst:
                for rec in cst.getCallSiteRecords():
                    lp = rec.getLandingPad()
                    cs = rec.getCallSite()
                    if lp and lp.getOffset() != 0:
                        rng = f"[{cs.getMinAddress()}..{cs.getMaxAddress()}]"
                        results.append((rng, lp.getOffset()))
        if results:
            return results
    except Exception:
        pass

    # Strategy 2: .gcc_except_table data cross-references
    try:
        ref_mgr = currentProgram.getReferenceManager()
        mem     = currentProgram.getMemory()
        body    = func.getBody()
        for block in mem.getBlocks():
            if block.getName() not in ('.gcc_except_table', '__gcc_except_table'):
                continue
            blk_end  = block.getEnd()
            ref_iter = ref_mgr.getReferenceIterator(block.getStart())
            for ref in ref_iter:
                if ref.getFromAddress().compareTo(blk_end) > 0:
                    break
                target = ref.getToAddress()
                if body.contains(target) and ref.getReferenceType().isData():
                    results.append(("(range from xref)", target.getOffset()))
    except Exception:
        pass

    return results


def annotate_eh_callsites(func, pcode):
    """
    GAP fix: EH_CLEANUP_NOT_SURFACED.
    Prepend TOOLKIT_NOTEs describing EH landing pads found in this function,
    so the LLM knows exception cleanup paths exist even without CFG edges.

    Returns (annotated_pcode, list_of_landing_pad_va_ints).
    """
    callsites = extract_eh_callsites(func)
    if not callsites:
        return pcode, []

    lines = [
        "/* TOOLKIT_NOTE: EH_CLEANUP_NOT_SURFACED — C++ exception handling paths present.",
        f"   {len(callsites)} protected region(s) map to landing pad(s) below.",
        "   Landing pads handle RAII destructors, catch clauses, and cleanup blocks.",
        "   Ghidra has NO CFG edges to these paths — they only execute on exception throw.",
        "   The functions at the landing pad VAs listed below are the actual handlers. */"
    ]
    for rng, lp_va in callsites:
        lines.append(f"/* EH_CALLSITE: protected {rng} → landing_pad 0x{lp_va:x} */")

    return "\n".join(lines) + "\n" + pcode, [lp_va for _, lp_va in callsites]


def annotate_stack_artifacts(pcode):
    """
    GAP-2 fix: CALLING_CONV_ARTIFACT.
    When Ghidra shows 'in_stack_XXXXXXXXXXXXXXXX' as a function call argument,
    the decompiler failed to resolve a local array address due to calling-
    convention confusion. Flag it so the LLM knows to treat it as a local
    variable, not a raw pointer value.
    """
    if not _re.search(r'\bin_stack_[0-9a-f]{4,}\b', pcode):
        return pcode
    note = ("/* TOOLKIT_NOTE: 'in_stack_XXXX' arguments below are DECOMPILER_ARTIFACTs"
            " -- stack-relative pointers Ghidra could not resolve."
            " Treat as references to local stack arrays, not literal pointer values. */\n")
    return note + pcode


def annotate_pointer_tables(pcode, global_arrays):
    """
    GAP-3+4 fix: RDATA_POINTER_TABLE_NOT_DEREFERENCED + INDIRECT_CALL_TARGETS_UNRESOLVED.
    For any global_array with resolved pointer_entries, prepend a TOOLKIT_NOTE
    so the LLM sees string values and function names without needing to follow
    pointers manually.
    """
    notes = []
    for name, ginfo in global_arrays.items():
        entries = ginfo.get("pointer_entries", [])
        if not entries:
            continue
        lines = [f"/* TOOLKIT_NOTE: {name} is a pointer table ({len(entries)} entries resolved):"]
        for i, e in enumerate(entries):
            if e["type"] == "function":
                lines.append(f"   [{i}] -> {e['name']}() @ {e['va']}")
            elif e["type"] == "string":
                lines.append(f'   [{i}] -> "{e["value"]}" @ {e["va"]}')
            else:
                lines.append(f"   [{i}] -> data @ {e['va']}")
        lines.append("*/")
        notes.append("\n".join(lines))
    if notes:
        pcode = "\n".join(notes) + "\n" + pcode
    return pcode


def annotate_signed_negatives(pcode):
    """
    GAP: SIGNED_CHAR_NEGATION.
    Ghidra represents uint8_t constants > 0x7F as negative signed chars
    (e.g., -0x56 instead of 0xAA). Annotate comparison patterns with the
    unsigned equivalent so the LLM doesn't burn a reasoning hop on the conversion.
    """
    def add_unsigned(m):
        neg_val = int(m.group(1), 16)
        unsigned = (0x100 - neg_val) & 0xFF
        return f"{m.group(0)} /* 0x{unsigned:02x} */"
    return _re.sub(r'== -0x([0-9a-fA-F]{1,2})\b', add_unsigned, pcode)


def annotate_ghidra_intrinsics(pcode):
    """
    GAP: CONCAT11_SEMANTICS, CONCAT44_SEMANTICS.
    Explain Ghidra-specific intrinsic functions that are not standard C.
    CONCAT11(hi, lo) = (hi << 8) | lo = big-endian 16-bit read.
    CONCAT44(hi, lo) = (hi << 32) | lo = 64-bit value from two 32-bit halves.
    """
    notes = []
    if "CONCAT11(" in pcode or "CONCAT22(" in pcode:
        notes.append("/* TOOLKIT_NOTE: CONCAT11(hi_byte, lo_byte) = (hi_byte << 8) | lo_byte"
                     " -- Ghidra's big-endian 2-byte concatenation intrinsic."
                     " First argument is the HIGH byte (MSB). This indicates a big-endian uint16 read. */")
    if "CONCAT44(" in pcode:
        notes.append("/* TOOLKIT_NOTE: CONCAT44(hi_dword, lo_dword) = ((uint64_t)hi_dword << 32) | lo_dword"
                     " -- Ghidra reconstructs a 64-bit value from two 32-bit halves."
                     " Appears in RDTSC/timestamp arithmetic where Ghidra splits 64-bit registers. */")
    if not notes:
        return pcode
    return "\n".join(notes) + "\n" + pcode


# Win32 constant values that have unambiguous single meanings.
# Only values that cannot be confused with other contexts are listed.
_WIN32_CONSTANTS = {
    # Predefined HKEY handles (64-bit sign-extended from 0x8000000X)
    "0xffffffff80000000": "HKEY_CLASSES_ROOT",
    "0xffffffff80000001": "HKEY_CURRENT_USER",
    "0xffffffff80000002": "HKEY_LOCAL_MACHINE",
    "0xffffffff80000003": "HKEY_USERS",
    "0xffffffff80000005": "HKEY_CURRENT_CONFIG",
    # Registry access masks (frequently appearing combos)
    "0x20019":  "KEY_READ",
    "0x20119":  "KEY_READ|KEY_WOW64_64KEY",
    "0x2001f":  "KEY_WRITE",
    "0xf003f":  "KEY_ALL_ACCESS",
    "0x20000":  "STANDARD_RIGHTS_READ",
    "0x0100":   "KEY_WOW64_64KEY",
    "0x0200":   "KEY_WOW64_32KEY",
    # Registry value types
    "0x1":  "REG_SZ",
    "0x2":  "REG_EXPAND_SZ",
    "0x3":  "REG_BINARY",
    "0x4":  "REG_DWORD",
    # CryptProtect/Unprotect flags (only annotate when adjacent to DPAPI call)
    # (handled contextually below)
    # Process/thread access rights
    "0x1f0fff": "PROCESS_ALL_ACCESS",
    "0x400":    "PROCESS_QUERY_INFORMATION",
    # Common NTSTATUS / Win32 error
    "0xc0000005": "STATUS_ACCESS_VIOLATION",
    "0xc0000034": "STATUS_OBJECT_NAME_NOT_FOUND",
}

# Known variadic functions: name -> index of format-string argument (0-based)
_VARIADIC_FUNCS = {
    "printf":     0,
    "fprintf":    1,
    "sprintf":    1,
    "snprintf":   2,
    "wsprintfA":  1,
    "wsprintfW":  1,
    "wsprintfA":  1,
    "wsprintfW":  1,
}


_VIRTUALPROTECT_FUNCS = frozenset([
    "VirtualProtect", "VirtualProtectEx", "VirtualAlloc", "VirtualAllocEx",
])

# PAGE_* ref-table for the TOOLKIT_NOTE (not used for inline substitution).
_PAGE_PROTECT_NOTE = (
    "/* TOOLKIT_NOTE: VirtualProtect/VirtualAlloc flNewProtect (3rd arg) values: "
    "0x1=PAGE_NOACCESS, 0x2=PAGE_READONLY, 0x4=PAGE_READWRITE, "
    "0x10=PAGE_EXECUTE, 0x20=PAGE_EXECUTE_READ, 0x40=PAGE_EXECUTE_READWRITE, "
    "0x1000=MEM_COMMIT, 0x2000=MEM_RESERVE, 0x3000=MEM_COMMIT|MEM_RESERVE. "
    "The size argument (2nd arg) is NOT a protection flag. */"
)


def annotate_win32_constants(pcode):
    """
    GAP: API_FLAG_CONSTANTS_NOT_RESOLVED, VIRTUALPROTECT_FLAGS_NOT_ANNOTATED.
    Replace unambiguous Win32 constant hex values with their symbolic names
    as inline comments. For VirtualProtect/VirtualAlloc, prepend a TOOLKIT_NOTE
    with PAGE_* reference table (in-line substitution is unsafe because the size
    argument shares values with PAGE_* constants).
    """
    for hex_val, sym_name in _WIN32_CONSTANTS.items():
        # Match the hex literal as a standalone token (word boundary), case-insensitive
        pattern = r'\b' + _re.escape(hex_val) + r'\b'
        replacement = f"{hex_val} /* {sym_name} */"
        pcode = _re.sub(pattern, replacement, pcode, flags=_re.IGNORECASE)

    # Prepend PAGE_* note if any Virtual* call is present
    for fn in _VIRTUALPROTECT_FUNCS:
        if fn in pcode:
            pcode = _PAGE_PROTECT_NOTE + "\n" + pcode
            break
    return pcode


def annotate_variadic_format(pcode):
    """
    GAP: VARIADIC_ARG_NOT_CAPTURED.
    Detect calls to known variadic functions where the format string contains
    more % specifiers than the decompiler captured as arguments. Emit a
    TOOLKIT_NOTE warning so the LLM knows arguments are missing.
    """
    notes = []
    for fname, fmt_idx in _VARIADIC_FUNCS.items():
        # Find calls: fname(arg0, arg1, ... "format_str", ...)
        # Simplified: find fname followed by a format string literal in the call
        call_pat = _re.compile(
            r'\b' + _re.escape(fname) + r'\s*\(([^;]*?)"([^"]*?)"\s*(\)|,\s*\))',
            _re.DOTALL
        )
        for m in call_pat.finditer(pcode):
            args_before = m.group(1)
            fmt_str     = m.group(2)
            trailing    = m.group(3)
            # Count format specifiers (% not followed by another %)
            n_specs = len(_re.findall(r'%[^%]', fmt_str))
            if n_specs == 0:
                continue
            # Are there captured args AFTER the format string?
            has_trailing_args = trailing.strip() not in (')', ',)')
            captured_after = 0 if not has_trailing_args else 1  # conservative estimate
            if n_specs > captured_after:
                missing = n_specs - captured_after
                notes.append(
                    f"/* TOOLKIT_NOTE: {fname}() format string \"{fmt_str[:40]}\" expects"
                    f" {n_specs} value arg(s) but decompiler captured ~{captured_after}."
                    f" {missing} arg(s) likely passed in registers and NOT shown."
                    f" Infer missing arg(s) from surrounding context (loop variable, array element). */"
                )
    if notes:
        pcode = "\n".join(notes) + "\n" + pcode
    return pcode


# ── Field access annotation (cross-function type propagation) ────────────────

_FIELD_MAP_CACHE = None   # lazy; None = not yet loaded

def _load_field_map() -> dict:
    """
    Load confirmed offset→name mappings from knowledge_bus (min_stability=COMMON).
    Returns a merged flat dict {offset_hex: field_name} across all structs.
    When the same offset is claimed by two different structs, that offset is
    dropped (ambiguous) rather than annotating with the wrong name.
    """
    global _FIELD_MAP_CACHE
    if _FIELD_MAP_CACHE is not None:
        return _FIELD_MAP_CACHE
    try:
        from knowledge_bus import get_field_map
        all_maps = get_field_map(min_stability="EPHEMERAL")
        merged: dict = {}
        conflicts: set = set()
        for struct_key, offsets in all_maps.items():
            for off_hex, fname in offsets.items():
                if off_hex in conflicts:
                    continue
                if off_hex in merged and merged[off_hex] != fname:
                    conflicts.add(off_hex)
                    del merged[off_hex]
                else:
                    merged[off_hex] = fname
        _FIELD_MAP_CACHE = merged
        if merged:
            print(f"  [FIELDS] Loaded {len(merged)} confirmed field offset(s) from knowledge_bus: "
                  + ", ".join(f"{k}→{v}" for k, v in sorted(merged.items())))
    except Exception as _fe:
        _FIELD_MAP_CACHE = {}
        print(f"  [FIELDS] knowledge_bus not available ({_fe}), skipping field annotations")
    return _FIELD_MAP_CACHE


_MEMORY_STATE_CACHE = None   # lazy; None = not yet loaded

def _load_memory_state_map() -> dict:
    """
    Load confirmed memory state transitions from knowledge_bus.
    Returns {ghidra_va_hex: {before_hex: after_hex, 'label': 'section+offset'}}
    Only includes observations with min_stability=COMMON.

    The KB stores runtime section offsets; we reconstruct Ghidra VAs using the
    program's image_base + section VRVAs when those are available via the Ghidra API.
    Falls back to section+offset labels when VA reconstruction is not possible.
    """
    global _MEMORY_STATE_CACHE
    if _MEMORY_STATE_CACHE is not None:
        return _MEMORY_STATE_CACHE
    _MEMORY_STATE_CACHE = {}
    try:
        from knowledge_bus import get_observations
        obs = get_observations(obs_type="memory_state_change", min_stability="COMMON")
        for o in obs:
            p   = o["payload"]
            sec = p.get("section", "?")
            off = p.get("offset", "0x0")
            bef = p.get("before", "0x0")
            aft = p.get("after", "0x0")
            fid = p.get("func_id", "?")
            label = f"{sec}+{off}"
            key   = label   # keyed by section+offset for Ghidra annotation lookup
            _MEMORY_STATE_CACHE[key] = {
                "before": bef, "after": aft,
                "func_id": fid, "section": sec, "offset": off,
            }
        if _MEMORY_STATE_CACHE:
            print(f"  [STATE] Loaded {len(_MEMORY_STATE_CACHE)} memory state transition(s) from KB")
    except Exception:
        pass
    return _MEMORY_STATE_CACHE


def annotate_memory_state(func, pcode: str) -> str:
    """
    GAP: GLOBAL_STATE_NOT_SURFACED.
    When the knowledge_bus has confirmed memory_state_change observations for
    functions in this calltree, prepend a TOOLKIT_NOTE listing which globals
    change and what values they transition through.

    This converts the classify.run() MemoryObserver findings into static
    annotations visible to the LLM reasoning pass.
    """
    state_map = _load_memory_state_map()
    if not state_map:
        return pcode

    # Match by function name or VA — find observations for this specific function
    func_name = str(func.getName()) if func is not None else ""
    func_va   = f"0x{func.getEntryPoint().getOffset():x}" if func is not None else ""

    relevant = [v for v in state_map.values()
                if v["func_id"] == func_name or v["func_id"] == func_va]
    if not relevant:
        return pcode

    lines = [
        "/* TOOLKIT_NOTE: GLOBAL_STATE_NOT_SURFACED — dynamic analysis confirmed state mutations.",
        f"   {len(relevant)} global(s) change when {func_name} is called:",
    ]
    for r in relevant:
        lines.append(
            f"   {r['section']}+{r['offset']}  {r['before']} → {r['after']}  (CONFIRMED by memory observer)"
        )
    lines.append(
        "   These are SIDE EFFECTS — the function's primary output is state change, not return value. */"
    )
    return "\n".join(lines) + "\n" + pcode


def annotate_field_accesses(pcode: str) -> str:
    """
    GAP: STRUCT_FIELD_NAMES_NOT_PROPAGATED.
    Inject /* ->field_name */ comments at confirmed struct field offsets.

    Matches pointer arithmetic context: `+ 0xNN` immediately followed by `)` or `,`
    as produced by Ghidra's decompiler (e.g. `*(int *)(param_1 + 0x18)`).
    Skips sites already annotated (/* already present after the offset).
    """
    field_map = _load_field_map()
    if not field_map:
        return pcode
    for off_hex, field_name in field_map.items():
        try:
            off_int = int(off_hex, 16)
        except ValueError:
            continue
        hex_str = f"0x{off_int:x}"
        # + 0xNN)  or  + 0xNN,  — but not when already annotated
        pat = _re.compile(
            r'(\+\s*)(' + _re.escape(hex_str) + r')(?!\s*/\*)(?=\s*[\),])',
            _re.IGNORECASE,
        )
        replacement = r'\g<1>\g<2>' + f" /* ->{field_name} */"
        pcode = pat.sub(replacement, pcode)
    return pcode


# ── Extension system ──────────────────────────────────────────────────────────

def _load_extensions():
    """Load all .json extension files from re_toolkit/extensions/."""
    ext_dir = os.path.join(_here, "extensions")
    if not os.path.isdir(ext_dir):
        return []
    exts = []
    for fname in sorted(os.listdir(ext_dir)):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(ext_dir, fname), encoding="utf-8") as fh:
                    exts.append(json.load(fh))
            except Exception as e:
                print(f"  [WARN] extensions/{fname}: {e}")
    return exts


def _detect_active_extensions(functions, all_extensions):
    """Scan named_callees across all functions; return extensions whose triggers match."""
    all_callee_names = set()
    for info in functions:
        all_callee_names.update(info.get("named_callees", []))
    active = []
    for ext in all_extensions:
        hit = set(ext.get("triggers", [])) & all_callee_names
        if hit:
            active.append(ext)
            print(f"  [EXT] {ext['family']}: triggered by {sorted(hit)[:4]}")
    return active


def _split_call_args(args_str):
    """Split comma-separated call arguments, respecting parenthesis depth."""
    args, depth, cur = [], 0, []
    for ch in args_str:
        if ch == '(':
            depth += 1
            cur.append(ch)
        elif ch == ')':
            depth -= 1
            cur.append(ch)
        elif ch == ',' and depth == 0:
            args.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        args.append(''.join(cur).strip())
    return args


def _parse_int_literal(s):
    """Parse a hex or decimal integer literal string. Returns None on failure."""
    s = s.strip()
    try:
        return int(s, 16) if (s.startswith('0x') or s.startswith('0X')) else int(s)
    except (ValueError, TypeError):
        return None


def _match_ext_val(val_int, table):
    """Look up val_int in an extension constant dict (keys are '0x...' strings)."""
    for key_str, label in table.items():
        if key_str == "comment":
            continue
        try:
            if int(key_str, 0) == val_int:
                return label
        except (ValueError, TypeError):
            pass
    return None


def annotate_from_extension(pcode, ext):
    """
    Apply one extension's three annotation modes to pseudocode.
    Returns (annotated_pcode, n_hits).

    Mode 1 — call_annotations: arg-position-specific inline comments for named calls.
    Mode 2 — comparison_annotations: inline comments on == / != literal values.
    Mode 3 — global_sentinels: unconditional word-boundary replacement for unambiguous values.
    """
    n_hits = 0

    # Mode 1: call_annotations
    for func_name, arg_table in ext.get("call_annotations", {}).items():
        call_start_pat = _re.compile(r'\b' + _re.escape(func_name) + r'\s*\(')
        parts = []
        last = 0
        for m in call_start_pat.finditer(pcode):
            depth = 1
            i = m.end()
            while i < len(pcode) and depth > 0:
                if pcode[i] == '(':
                    depth += 1
                elif pcode[i] == ')':
                    depth -= 1
                i += 1
            # pcode[m.end()-1 : i] = '(args...)'
            args_str = pcode[m.end():i - 1]
            args = _split_call_args(args_str)
            new_args = list(args)
            modified = False
            for idx_str, val_table in arg_table.items():
                idx = int(idx_str)
                if idx >= len(args):
                    continue
                raw = args[idx].strip()
                val = _parse_int_literal(raw)
                if val is None or '/*' in raw:
                    continue
                label = _match_ext_val(val, val_table)
                if label:
                    new_args[idx] = f"{raw} /* {label} */"
                    modified = True
                    n_hits += 1
            parts.append(pcode[last:m.start()])
            if modified:
                parts.append(func_name + '(' + ', '.join(new_args) + ')')
            else:
                parts.append(pcode[m.start():i])
            last = i
        parts.append(pcode[last:])
        pcode = ''.join(parts)

    # Mode 2: comparison_annotations
    comp_anns = {k: v for k, v in ext.get("comparison_annotations", {}).items()
                 if k != "comment"}
    if comp_anns:
        cmp_pat = _re.compile(r'([!=]=\s*)(0[xX][0-9a-fA-F]+|\b\d+\b)')
        def replace_cmp(m):
            nonlocal n_hits
            val = _parse_int_literal(m.group(2))
            if val is None:
                return m.group(0)
            label = _match_ext_val(val, comp_anns)
            if label and not m.string[m.end():m.end() + 3].startswith(' /*'):
                n_hits += 1
                return f"{m.group(1)}{m.group(2)} /* {label} */"
            return m.group(0)
        pcode = cmp_pat.sub(replace_cmp, pcode)

    # Mode 3: global_sentinels
    for val_str, label in ext.get("global_sentinels", {}).items():
        if val_str == "comment":
            continue
        sent_pat = _re.compile(r'\b' + _re.escape(val_str) + r'\b(?!\s*/\*)',
                               _re.IGNORECASE)
        def replace_sent(m, _lbl=label, _val=val_str):
            nonlocal n_hits
            n_hits += 1
            return f"{_val} /* {_lbl} */"
        pcode = sent_pat.sub(replace_sent, pcode)

    return pcode, n_hits


def apply_extensions_pass(functions, active_extensions):
    """
    Post-walk pass: apply all active extension annotations to every function's
    pseudocode. Prepends a DOMAIN_ACTIVE TOOLKIT_NOTE to functions where at
    least one constant was annotated, so the LLM knows which domain physics
    were injected and can query unknown literals via resolve_constant.py.
    """
    if not active_extensions:
        return

    families = ", ".join(e["family"] for e in active_extensions)
    domain_hdr = (
        f"/* TOOLKIT_NOTE: DOMAIN_ACTIVE [{families}] — "
        "domain-specific constants annotated inline from extensions/. "
        "Unknown numeric literals: py -3.13 resolve_constant.py <value> */"
    )

    total_annotated = 0
    for info in functions:
        pcode = info.get("pseudocode")
        if not pcode or pcode.startswith("/* FAILED") or pcode.startswith("/* EXCEPTION"):
            continue
        hits = 0
        for ext in active_extensions:
            pcode, n = annotate_from_extension(pcode, ext)
            hits += n
        if hits > 0:
            if domain_hdr not in pcode:
                pcode = domain_hdr + "\n" + pcode
            total_annotated += 1
        info["pseudocode"] = pcode

    print(f"  {total_annotated} function(s) had constants annotated.")


def func_va(func):
    return func.getEntryPoint().getOffset()

def get_string_refs(char_array_addr):
    """
    Return functions that reference a NativeAOT frozen string near char_array_addr.
    Probes offsets 0, -0x10, -0x0c, -8, -4, +4, +8, +0x10 to catch wherever
    Ghidra recorded the xref. Floor: XREF_HEADLESS_GAP if none found.
    """
    ref_mgr  = currentProgram.getReferenceManager()
    fm       = currentProgram.getFunctionManager()
    as_      = currentProgram.getAddressFactory().getDefaultAddressSpace()
    funcs    = set()
    base_off = char_array_addr.getOffset()

    for delta in (0, -0x10, -0x0c, -8, -4, 4, 8, 0x10):
        candidate = base_off + delta
        if candidate < 0:
            continue
        try:
            addr = as_.getAddress(candidate)
        except Exception:
            continue
        for ref in ref_mgr.getReferencesTo(addr):
            f = fm.getFunctionContaining(ref.getFromAddress())
            if f:
                funcs.add(f)
    return funcs

def is_library_or_thunk(func):
    return (func.isExternal() or func.isThunk() or
            str(func.getEntryPoint()).startswith("EXTERNAL"))


def get_computed_jump_targets(func):
    """
    Return functions reachable via computed jumps (JMP [table+reg*8]) within func.

    Ghidra's switch-table analysis creates caseD_N functions and adds computed
    references in the reference manager, but func.getCalledFunctions() only
    returns DIRECT CALL targets — it misses jump-table dispatch entirely.
    This is the root cause of the 87% noise cluster on emulator binaries where
    instruction dispatch goes through switch tables, not direct calls.

    Uses ref_mgr.getReferencesFrom(addr) per instruction — safe per
    feedback_ghidra_api.md (getReferencesFrom(single_addr) exists;
    getReferencesFromRange does NOT).
    """
    targets = set()
    try:
        listing  = currentProgram.getListing()
        ref_mgr  = currentProgram.getReferenceManager()
        func_mgr = currentProgram.getFunctionManager()
        body     = func.getBody()
        self_va  = func_va(func)

        instr_iter = listing.getInstructions(body, True)
        for instr in instr_iter:
            flow = instr.getFlowType()
            # Only care about computed jumps/calls (switch tables, fn-ptr calls)
            if not (flow.isComputed() and (flow.isJump() or flow.isCall())):
                continue
            refs = ref_mgr.getReferencesFrom(instr.getAddress())
            for ref in refs:
                rtype = ref.getReferenceType()
                if not (rtype.isComputed() or rtype.isJump() or rtype.isCall()):
                    continue
                target_addr = ref.getToAddress()
                target_func = func_mgr.getFunctionAt(target_addr)
                if (target_func and
                        not is_library_or_thunk(target_func) and
                        func_va(target_func) != self_va):
                    targets.add(target_func)
    except Exception:
        pass
    return targets


def func_info(func):
    """
    Build the static fingerprint record for one function.

    Schema version 2: adds structural and call-graph signals beyond the original
    size + called_vas baseline.  All fields are populated from Ghidra's API at
    walk time (before decompile).  Pseudocode-derived fields (loop_count etc.)
    are filled in during the decompile pass and start as None.

    Signal taxonomy (mirrors dynamic/fingerprint.py for the static layer):
      CALL_GRAPH  — xref_count, callee_count, caller_count, is_recursive
      STRUCTURAL  — size, basic_block_count, param_count, stack_frame_size, has_varargs
      PCODE       — filled after decompile: loop_count, branch_count, switch_count,
                    const_count, has_float_ops, has_goto, pcode_len
      COMPOSITE   — cyclomatic_approx (= branch_count + switch_count + 1)
    """
    va = func_va(func)
    entry = func.getEntryPoint()

    # ── call-graph signals ────────────────────────────────────────────────────
    all_callers  = list(func.getCallingFunctions(monitor))
    all_callees  = list(func.getCalledFunctions(monitor))
    internal_callees = [c for c in all_callees if not is_library_or_thunk(c)]
    # Also include computed-jump targets (switch tables, fn-ptr dispatch)
    # These are invisible to getCalledFunctions() but visible in the reference manager
    computed_targets = get_computed_jump_targets(func)
    computed_new     = [t for t in computed_targets if t not in internal_callees]
    internal_callees = internal_callees + computed_new

    # xref_count: total incoming references (all types, not just function calls)
    # This is a stronger signal than caller_count — includes data refs, jumptable entries
    try:
        ref_mgr   = currentProgram.getReferenceManager()
        xref_count = sum(1 for _ in ref_mgr.getReferencesTo(entry))
    except Exception:
        xref_count = len(all_callers)   # fallback: use caller count

    # is_recursive: function directly calls itself
    self_va = va
    is_recursive = any(func_va(c) == self_va for c in all_callees)

    # ── structural signals ────────────────────────────────────────────────────
    body = func.getBody()
    basic_block_count = body.getNumAddressRanges()   # address ranges ≈ basic blocks

    try:
        frame      = func.getStackFrame()
        stack_size = frame.getLocalSize()
    except Exception:
        stack_size = -1

    try:
        sig        = func.getSignature()
        param_count = len(sig.getArguments())
        ret_type    = str(sig.getReturnType())
    except Exception:
        param_count = -1
        ret_type    = "unknown"

    return {
        # ── identity ─────────────────────────────────────────────────────────
        "va":              f"0x{va:x}",
        "name":            str(func.getName()),
        "is_thunk":        func.isThunk(),
        "is_external":     func.isExternal(),
        "fingerprint_ver": 2,

        # ── call-graph signals ────────────────────────────────────────────────
        "called_vas":      [f"0x{v:x}" for v in [func_va(c) for c in internal_callees]],
        "named_callees":   [str(c.getName()) for c in all_callees],
        "calling_names":   [str(c.getName()) for c in all_callers[:20]],  # uncapped→20
        "caller_count":    len(all_callers),       # fan-in (full, not capped)
        "callee_count":    len(all_callees),       # fan-out (all, including external)
        "xref_count":      xref_count,             # total incoming references (incl. data)
        "is_recursive":    is_recursive,

        # ── structural signals ────────────────────────────────────────────────
        "size":            body.getNumAddresses(), # instruction-address count
        "basic_block_count": basic_block_count,
        "param_count":     param_count,
        "return_type":     ret_type,
        "stack_frame_size": stack_size,
        "has_varargs":     func.hasVarArgs(),

        # ── pseudocode-derived signals (filled in decompile pass) ─────────────
        "pcode_len":       None,   # len(pseudocode) in chars
        "loop_count":      None,   # while/for/do occurrences
        "branch_count":    None,   # if-statement occurrences
        "switch_count":    None,   # switch-statement occurrences
        "const_count":     None,   # numeric constant occurrences
        "has_float_ops":   None,   # float/double keyword presence
        "has_goto":        None,   # unstructured control flow
        "cyclomatic_approx": None, # branch_count + switch_count + 1

        # ── pipeline metadata ─────────────────────────────────────────────────
        "depth":           None,
        "floors":          [],
        "global_arrays":   {},
        "eh_landing_pads": [],
        "pseudocode":      None,
    }

# ── Main walk ─────────────────────────────────────────────────────────────────

def walk_tree(seed_funcs, max_depth):
    """BFS from seed_funcs into callees up to max_depth. Leaves decompiled first."""
    visited = {}
    queue   = collections.deque()
    for f in seed_funcs:
        v = func_va(f)
        if v not in visited:
            visited[v] = 0
            queue.append((f, 0))

    order = []

    while queue:
        func, depth = queue.popleft()
        info = func_info(func)
        info["depth"] = depth
        order.append(info)
        print(f"  [d={depth}] {info['name']}  {info['va']}  "
              f"{info['size']} addrs  {len(info['called_vas'])} callees")

        if depth < max_depth:
            # Direct calls
            all_next = list(func.getCalledFunctions(monitor))
            # + computed jump targets (switch tables, fn-ptr dispatch)
            all_next += list(get_computed_jump_targets(func))
            for callee in all_next:
                if is_library_or_thunk(callee):
                    continue
                cv = func_va(callee)
                if cv not in visited:
                    visited[cv] = depth + 1
                    queue.append((callee, depth + 1))

    total = len(order)
    print(f"\nDecompiling {total} functions (leaves first)...")
    va_to_info = {info["va"]: info for info in order}

    for_decompile = sorted(order, key=lambda x: (-x["depth"], x["va"]))
    for i, info in enumerate(for_decompile):
        va   = int(info["va"], 16)
        addr = get_addr(va)
        func = ensure_function(addr)
        if func is None:
            info["pseudocode"] = "/* could not create function */"
            info["floors"].append("DECOMPILER_FAILED")
            continue
        print(f"  [{i+1}/{total}] decompiling {info['name']} {info['va']} ...")
        pcode = decompile(func)
        if pcode and not pcode.startswith("/* FAILED") and not pcode.startswith("/* EXCEPTION"):
            # GAP-1: extract global arrays referenced in this function
            info["global_arrays"] = extract_global_arrays(pcode)
            # GAP fix: also follow raw .rdata data refs (catches tables not named in pseudocode)
            for k, v in extract_rdata_refs(func).items():
                if k not in info["global_arrays"]:
                    info["global_arrays"][k] = v
            if info["global_arrays"]:
                n_ptr = sum(len(g.get("pointer_entries", [])) for g in info["global_arrays"].values())
                print(f"         global arrays: {list(info['global_arrays'].keys())}"
                      + (f"  ({n_ptr} ptr entries resolved)" if n_ptr else ""))
                # Add function pointer table targets to called_vas so the call graph
                # correctly reflects dispatch-table-mediated calls (not just direct calls).
                # Without this, handlers reachable only via dispatch tables appear as noise.
                for ginfo in info["global_arrays"].values():
                    for entry in ginfo.get("pointer_entries", []):
                        if entry.get("type") == "function" and entry["va"] not in info["called_vas"]:
                            info["called_vas"].append(entry["va"])
                            fn_name = entry.get("name", entry["va"])
                            if fn_name not in info["named_callees"]:
                                info["named_callees"].append(fn_name)
            # GAP-2: annotate stack-relative decompiler artifacts
            pcode = annotate_stack_artifacts(pcode)
            # GAP-3+4: annotate pointer tables (string and function targets)
            pcode = annotate_pointer_tables(pcode, info["global_arrays"])
            # GAP: annotate signed-char negative constants
            pcode = annotate_signed_negatives(pcode)
            # GAP: explain Ghidra intrinsics (CONCAT11 etc.)
            pcode = annotate_ghidra_intrinsics(pcode)
            # GAP: annotate unambiguous Win32 API constants
            pcode = annotate_win32_constants(pcode)
            # GAP: warn about missing variadic args (printf/wsprintf family)
            pcode = annotate_variadic_format(pcode)
            # GAP: cross-function field names from knowledge_bus
            pcode = annotate_field_accesses(pcode)
            # GAP: confirmed global state mutations from dynamic memory observer
            pcode = annotate_memory_state(func, pcode)
            # GAP fix: EH_CLEANUP_NOT_SURFACED — annotate landing pads from .gcc_except_table
            pcode, lp_vas = annotate_eh_callsites(func, pcode)
            if lp_vas:
                info["eh_landing_pads"] = [f"0x{v:x}" for v in lp_vas]
                print(f"         EH landing pads: {info['eh_landing_pads']}")
        info["pseudocode"] = pcode
        if pcode and "FLOOR:" in pcode:
            for token in pcode.split():
                if token.startswith("FLOOR:"):
                    info["floors"].append(token[6:].rstrip("*/"))

        # ── pseudocode-derived static fingerprint signals ─────────────────────
        # Filled here so they're in the JSON alongside structural signals from func_info().
        # Regex is cheap; running against raw pcode (before annotations) avoids counting
        # TOOLKIT_NOTE comments as branches/loops.
        raw_pcode = pcode or ""
        info["pcode_len"]     = len(raw_pcode)
        info["loop_count"]    = (raw_pcode.count("while (") + raw_pcode.count("for (")
                                 + raw_pcode.count("do {"))
        info["branch_count"]  = raw_pcode.count("if (")
        info["switch_count"]  = raw_pcode.count("switch (")
        info["const_count"]   = len(_re.findall(r'\b0[xX][0-9a-fA-F]+\b|\b[1-9][0-9]{2,}\b',
                                                raw_pcode))
        info["has_float_ops"] = bool(_re.search(r'\b(float|double|FLOAT|DOUBLE)\b', raw_pcode))
        info["has_goto"]      = "goto " in raw_pcode
        bc = info["branch_count"] or 0
        sc = info["switch_count"] or 0
        info["cyclomatic_approx"] = bc + sc + 1   # McCabe approximation from pseudocode

        # ── SIMD vectorization detection ──────────────────────────────────────
        # Auto-vectorization by GCC/Clang/MSVC transforms scalar loops into SIMD
        # operations that Ghidra decompiles into unreadable register-slice notation.
        # When detected, pseudocode is unreliable — behavioral metrics (I/O fingerprint)
        # are the primary signal. These patterns are architecture/compiler-independent
        # in Ghidra's output (Ghidra always uses auVar/register-slice notation for SIMD).
        simd_signals = [
            bool(_re.search(r'\bauVar\d+\s*\[1[26]\]', raw_pcode)),      # 16/32-byte SIMD var
            bool(_re.search(r'\._[048]_[248]_', raw_pcode)),              # register slicing
            bool(_re.search(r'\bin_register_[0-9a-f]{8}\b', raw_pcode)), # unresolved SIMD reg
            bool(_re.search(r'\b__m(128|256|512)[id]?\b', raw_pcode)),    # explicit SIMD type
            bool(_re.search(r'\b_mm_[a-z]', raw_pcode)),                  # SSE/AVX intrinsic
        ]
        is_simd = sum(simd_signals) >= 2   # require 2+ signals to avoid false positives
        info["is_simd_vectorized"] = is_simd

        if is_simd and not pcode.startswith("/* TOOLKIT_NOTE: SIMD"):
            simd_note = (
                "/* TOOLKIT_NOTE: SIMD_VECTORIZED — compiler auto-vectorization has "
                "transformed this function's scalar logic into SIMD register operations. "
                "Ghidra's pseudocode (auVar/register-slice notation) is unreliable here. "
                "The function's I/O behavioral metrics are more informative than static reading. "
                "Focus on: callers, callees, constants, and string refs rather than "
                "the SIMD register arithmetic. */"
            )
            pcode = simd_note + "\n" + pcode
            info["pseudocode"] = pcode

    return order, visited

# ── Entry ─────────────────────────────────────────────────────────────────────

def main():
    seeds_env = os.environ.get("GHIDRA_SEEDS", "")
    env_seeds = [int(x, 16) for x in seeds_env.split(",") if x.strip()]
    max_depth = int(os.environ.get("GHIDRA_DEPTH", MAX_DEPTH_DEFAULT))
    out_path  = os.environ.get("GHIDRA_OUT",   OUT_DEFAULT)

    print(f"Program  : {currentProgram.getName()}")
    print(f"ImageBase: {currentProgram.getImageBase()}")
    print(f"MaxDepth : {max_depth}")
    print(f"Output   : {out_path}")
    print()

    fm = currentProgram.getFunctionManager()
    seed_funcs = set()
    floors = []

    # Pass 1: direct function VAs (always reliable)
    func_seeds = env_seeds if env_seeds else FUNCTION_SEEDS_DEFAULT
    print(f"Pass 1 -- direct function seeds ({len(func_seeds)}):")
    for va in func_seeds:
        addr = get_addr(va)
        func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if func and not is_library_or_thunk(func):
            seed_funcs.add(func)
            print(f"  [OK ] 0x{va:x} -> {func.getName()}")
        else:
            func = ensure_function(addr)
            if func and not is_library_or_thunk(func):
                seed_funcs.add(func)
                print(f"  [NEW] 0x{va:x} -> {func.getName()} (created)")
            else:
                print(f"  [--] 0x{va:x} -> not found / is thunk")

    # Pass 2: string xref seeds (best-effort, often fails in headless)
    if not env_seeds:
        print(f"\nPass 2 -- string xref seeds ({len(STRING_SEEDS_DEFAULT)}):")
        xref_gap_count = 0
        for va in STRING_SEEDS_DEFAULT:
            addr = get_addr(va)
            refs = get_string_refs(addr)
            if refs:
                for f in refs:
                    if f not in seed_funcs:
                        seed_funcs.add(f)
                        print(f"  [OK ] 0x{va:x} (string) -> {f.getName()} @ 0x{func_va(f):x}")
            else:
                xref_gap_count += 1
                print(f"  [--] 0x{va:x} -> no xrefs (XREF_HEADLESS_GAP)")
        if xref_gap_count:
            floors.append({
                "tag":   "XREF_HEADLESS_GAP",
                "count": xref_gap_count,
                "note":  "headless x86 Constant Reference Analyzer skipped these string xrefs",
            })

    if not seed_funcs:
        # Fallback: seed from PE exported functions (works when KNOWN_VAS are 0x0 placeholders)
        print("\nPass 1 resolved nothing — falling back to exported functions...")
        sym_table = currentProgram.getSymbolTable()
        from ghidra.program.model.symbol import SymbolType
        for sym in sym_table.getDefinedSymbols():
            if sym.isExternalEntryPoint() or sym.getSymbolType() == SymbolType.FUNCTION:
                func = fm.getFunctionAt(sym.getAddress())
                if func and not is_library_or_thunk(func):
                    seed_funcs.add(func)
        if seed_funcs:
            print(f"  Found {len(seed_funcs)} exported/defined function(s) as fallback seeds.")
        else:
            print("\nERROR: No seed functions resolved and no exports found.")
            print("Add known function VAs to ground_truth.KNOWN_VAS or set GHIDRA_SEEDS env var.")
            return

    print(f"\n{len(seed_funcs)} seed function(s).  Walking to depth {max_depth}...\n")
    functions, visited_vas = walk_tree(seed_funcs, max_depth)

    # Pass 3: decompile function pointer targets discovered via pointer tables
    # (fixes INDIRECT_CALL_TARGETS_UNRESOLVED — dispatch table bodies now in calltree)
    ptr_target_funcs = {}   # va_hex -> func
    for info in functions:
        for gname, ginfo in info.get("global_arrays", {}).items():
            for entry in ginfo.get("pointer_entries", []):
                if entry["type"] == "function":
                    va_hex = entry["va"]
                    va_int = int(va_hex, 16)
                    if va_int not in visited_vas and va_hex not in ptr_target_funcs:
                        try:
                            addr = get_addr(va_int)
                            func = ensure_function(addr)
                            if func and not is_library_or_thunk(func):
                                ptr_target_funcs[va_hex] = func
                        except Exception as _e:
                            print(f"  [WARN] pointer target {va_hex} not resolvable: {_e}")

    if ptr_target_funcs:
        print(f"\nPass 3 -- decompiling {len(ptr_target_funcs)} pointer-table function targets...")
        for va_hex, func in sorted(ptr_target_funcs.items()):
            print(f"  decompiling {func.getName()} {va_hex} ...")
            info = func_info(func)
            info["depth"] = -1
            info["floors"].append("POINTER_TABLE_TARGET")
            pcode = decompile(func)
            if pcode and not pcode.startswith("/* FAILED") and not pcode.startswith("/* EXCEPTION"):
                info["global_arrays"] = extract_global_arrays(pcode)
                for k, v in extract_rdata_refs(func).items():
                    if k not in info["global_arrays"]:
                        info["global_arrays"][k] = v
                pcode = annotate_stack_artifacts(pcode)
                pcode = annotate_pointer_tables(pcode, info["global_arrays"])
                pcode = annotate_signed_negatives(pcode)
                pcode = annotate_ghidra_intrinsics(pcode)
                pcode = annotate_win32_constants(pcode)
                pcode = annotate_variadic_format(pcode)
                pcode = annotate_field_accesses(pcode)
            info["pseudocode"] = pcode
            functions.append(info)
            visited_vas[func_va(func)] = -1

    # Pass 4: decompile EH landing pad functions surfaced during the main walk.
    # These are cleanup/catch handlers invisible in the happy-path CFG — without
    # decompiling them, the LLM cannot see what the exception cleanup does.
    eh_target_funcs = {}
    for info in functions:
        for lp_hex in info.get("eh_landing_pads", []):
            lp_va = int(lp_hex, 16)
            if lp_va not in visited_vas and lp_hex not in eh_target_funcs:
                try:
                    addr    = get_addr(lp_va)
                    lp_func = ensure_function(addr)
                    if lp_func and not is_library_or_thunk(lp_func):
                        eh_target_funcs[lp_hex] = lp_func
                except Exception as _e:
                    print(f"  [WARN] EH landing pad {lp_hex} not resolvable: {_e}")

    if eh_target_funcs:
        print(f"\nPass 4 -- decompiling {len(eh_target_funcs)} EH landing pad function(s)...")
        for va_hex, func in sorted(eh_target_funcs.items()):
            print(f"  decompiling {func.getName()} {va_hex} (EH handler)...")
            info = func_info(func)
            info["depth"] = -1
            info["floors"].append("EH_LANDING_PAD")
            pcode = decompile(func)
            if pcode and not pcode.startswith("/* FAILED") and not pcode.startswith("/* EXCEPTION"):
                info["global_arrays"] = extract_global_arrays(pcode)
                for k, v in extract_rdata_refs(func).items():
                    if k not in info["global_arrays"]:
                        info["global_arrays"][k] = v
                pcode = annotate_stack_artifacts(pcode)
                pcode = annotate_pointer_tables(pcode, info["global_arrays"])
                pcode = annotate_signed_negatives(pcode)
                pcode = annotate_ghidra_intrinsics(pcode)
                pcode = annotate_win32_constants(pcode)
                pcode = annotate_variadic_format(pcode)
                pcode = annotate_field_accesses(pcode)
                pcode, _ = annotate_eh_callsites(func, pcode)
            info["pseudocode"] = pcode
            functions.append(info)
            visited_vas[func_va(func)] = -1

    # Extension pass: detect active domain families and annotate constants
    print("\nExtension pass:")
    _all_exts = _load_extensions()
    if _all_exts:
        print(f"  Loaded {len(_all_exts)} extension file(s): "
              f"{[e['family'] for e in _all_exts]}")
        _active_exts = _detect_active_extensions(functions, _all_exts)
    else:
        _active_exts = []
        print("  No extension files found in extensions/.")
    if _active_exts:
        apply_extensions_pass(functions, _active_exts)
    else:
        print("  No domain-specific extensions triggered.")
    active_ext_names = [e["family"] for e in _active_exts]

    # Count named floors across all functions
    decompiler_failed = sum(1 for f in functions if "DECOMPILER_FAILED" in f.get("floors", []))
    if decompiler_failed:
        floors.append({
            "tag":   "DECOMPILER_FAILED",
            "count": decompiler_failed,
            "note":  "Ghidra decompiler could not produce pseudocode for these functions",
        })

    out = {
        "program":        str(currentProgram.getName()),
        "imagebase":      str(currentProgram.getImageBase()),
        "platform":       "x86_64 (little-endian)",
        "function_seeds": [hex(v) for v in (env_seeds or FUNCTION_SEEDS_DEFAULT)],
        "string_seeds":   [hex(v) for v in STRING_SEEDS_DEFAULT],
        "max_depth":      max_depth,
        "floors":         floors,
        "active_extensions": active_ext_names,
        "functions":      functions,
        "count":          len(functions),
    }

    # Graph topology pass: compute k-core, betweenness, graph_rank for each function.
    # Uses seed VAs to compute seed-relative betweenness (not global).
    # Adds noise_cluster flag to functions structurally isolated from seeds.
    try:
        _graph_mod_path = os.path.join(_here, "dynamic")
        if _graph_mod_path not in sys.path:
            sys.path.insert(0, _graph_mod_path)
        from graph_metrics import annotate_calltree as _annotate_graph
        _seed_va_set = {hex(v) for v in (env_seeds or FUNCTION_SEEDS_DEFAULT)
                        if v != 0}
        _annotate_graph(functions, seed_vas=_seed_va_set if _seed_va_set else None)
        _noise = sum(1 for f in functions if f.get("noise_cluster"))
        _max_k = max((f.get("k_core", 0) for f in functions), default=0)
        print(f"  Graph metrics: noise_cluster={_noise}/{len(functions)}  "
              f"max_k_core={_max_k}")
    except Exception as _ge:
        print(f"  [WARN] graph_metrics skipped: {_ge}")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    total_pcode = sum(len(x['pseudocode'] or '') for x in functions)
    ptr_extra = len(ptr_target_funcs)
    eh_extra  = len(eh_target_funcs)
    eh_sites  = sum(len(x.get('eh_landing_pads', [])) for x in functions)
    print(f"\nWrote {len(functions)} functions -> {out_path}")
    print(f"Total pseudocode: {total_pcode:,} chars")
    if ptr_extra:
        print(f"Pass 3 added {ptr_extra} pointer-table function(s) to calltree")
    if eh_sites:
        print(f"Pass 4 found {eh_sites} EH call site(s); added {eh_extra} landing pad function(s)")
    if floors:
        print(f"Named floors: {[fl['tag'] for fl in floors]}")

main()
