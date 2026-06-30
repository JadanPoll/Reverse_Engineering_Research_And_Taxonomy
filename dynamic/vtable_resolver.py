"""
dynamic/vtable_resolver.py - Dynamic COM vtable discovery via object inspection.

Load a DLL, call a factory export, read the vtable pointer from the returned
COM object, map each slot address back to a calltree VA.  Emits results to the
knowledge bus as synthetic call edges, closing the anchor propagation gap that
guard_dispatch_icall creates in statically analysed COM binaries.

Works for any COM-style object (IUnknown layout: first field = vtable pointer).
Also works for C-style vtables (structs of function pointers).

Usage (CLI):
    py -3.13 dynamic/vtable_resolver.py --calltree path/calltree.json
        --dll path/foo.dll --export CreateDXGIFactory
        --iid "{7b7166ec-21c7-44ae-b21a-c9ae321ae369}"
        --name IDXGIFactory [--max-slots 32]
"""
from __future__ import annotations
import ctypes, json, os, sys, argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pe_utils import PE


# ── GUID helper ──────────────────────────────────────────────────────────────

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_uint8 * 8),
    ]

    @classmethod
    def from_string(cls, s: str) -> "GUID":
        s = s.strip("{} ")
        parts = s.split("-")
        if len(parts) != 5:
            raise ValueError(f"Bad GUID format: {s!r}")
        g = cls()
        g.Data1 = int(parts[0], 16)
        g.Data2 = int(parts[1], 16)
        g.Data3 = int(parts[2], 16)
        for i, b in enumerate(bytes.fromhex(parts[3] + parts[4])):
            g.Data4[i] = b
        return g


# ── VTableResolver ────────────────────────────────────────────────────────────

class VTableResolver:
    """
    Load a PE DLL, resolve COM vtable slots to calltree VAs.

    The rebase formula is identical to DLLExecutor:
        ghidra_va = runtime_va - rebase
        rebase    = load_base  - image_base
    so ghidra_va = runtime_va - load_base + image_base = image_base + rva.
    """

    def __init__(self, dll_path: str, calltree_path: str):
        self.dll_path      = dll_path
        self.calltree_path = calltree_path

        with open(calltree_path, encoding="utf-8") as f:
            self.calltree = json.load(f)

        # VA → function lookup (Ghidra VAs stored as hex strings in calltree)
        self._va_to_fn: dict[int, dict] = {}
        for fn in self.calltree["functions"]:
            va = int(fn["va"], 16) if isinstance(fn["va"], str) else fn["va"]
            self._va_to_fn[va] = fn

        self.dll        = ctypes.CDLL(dll_path)
        load_base       = self.dll._handle
        self.pe         = PE(dll_path)
        self.image_base = self.pe.image_base
        self._rebase    = load_base - self.image_base

        # Build set of executable VA ranges from PE section table.
        # IMAGE_SCN_MEM_EXECUTE = 0x20000000
        _EXEC = 0x20000000
        self._exec_ranges: list[tuple[int, int]] = []   # for slot fn ptrs
        self._any_ranges:  list[tuple[int, int]] = []   # for vtable ptr itself
        for s in self.pe.sections:
            runtime_lo = load_base + s["vrva"]
            runtime_hi = runtime_lo + max(s["vsize"], 1)
            self._any_ranges.append((runtime_lo, runtime_hi))
            if s["chars"] & _EXEC:
                self._exec_ranges.append((runtime_lo, runtime_hi))

        if not self._exec_ranges:
            self._exec_ranges = self._any_ranges[:]

    # ── address helpers ───────────────────────────────────────────────────────

    def _in_dll(self, addr: int) -> bool:
        """True if addr falls in any DLL section (used for vtable pointer)."""
        return any(lo <= addr < hi for lo, hi in self._any_ranges)

    def _in_dll_exec(self, addr: int) -> bool:
        """True if addr falls in an executable DLL section (used for slot fn ptrs)."""
        return any(lo <= addr < hi for lo, hi in self._exec_ranges)

    def _to_ghidra(self, runtime_addr: int) -> int:
        return runtime_addr - self._rebase

    def _fn_at(self, ghidra_va: int) -> dict | None:
        return self._va_to_fn.get(ghidra_va)

    # ── core vtable walk ──────────────────────────────────────────────────────

    def walk_vtable(self, obj_ptr: int, max_slots: int = 64) -> dict[int, dict]:
        """
        Given a runtime pointer to a COM/vtable object, read its vtable and
        return {slot_index: {"runtime": addr, "ghidra_va": va, "name": str}}.
        Stops at the first null slot or address outside the DLL range.
        """
        if not obj_ptr:
            return {}
        try:
            vtbl_ptr = ctypes.c_uint64.from_address(obj_ptr).value
        except OSError:
            return {}

        if not self._in_dll(vtbl_ptr):
            return {}

        slots: dict[int, dict] = {}
        consecutive_outside = 0
        for i in range(max_slots):
            try:
                fn_ptr = ctypes.c_uint64.from_address(vtbl_ptr + i * 8).value
            except OSError:
                break

            if fn_ptr == 0:
                break

            if not self._in_dll_exec(fn_ptr):
                consecutive_outside += 1
                if consecutive_outside >= 3:
                    break
                continue
            consecutive_outside = 0

            gva  = self._to_ghidra(fn_ptr)
            fn   = self._fn_at(gva)
            name = fn["name"] if fn else f"FUN_{gva:#x}"
            slots[i] = {"runtime": fn_ptr, "ghidra_va": gva, "name": name}

        return slots

    # ── section scanner (runtime-initialized tables) ─────────────────────────

    def scan_section_for_fptrs(
        self,
        section_name: str = ".data",
        call_before: str | None = None,
        max_results: int = 2048,
    ) -> dict[int, dict]:
        """
        Scan a DLL section for runtime-initialized function pointers.

        Unlike walk_vtable() which reads from a single object pointer,
        this scans an ENTIRE section for any 8-byte value that falls within
        an executable section of the DLL.  Useful for emulators, game engines,
        and any C binary that fills dispatch tables at runtime (not compile-time).

        call_before: if set, call this named export before scanning so that
                     runtime initialization (e.g. retro_init) populates the tables.

        Returns {offset_in_section: {"runtime": addr, "ghidra_va": va, "name": str}}.
        Offset is the byte offset within the section where the pointer lives.
        """
        if call_before:
            try:
                fn = getattr(self.dll, call_before)
                fn.restype  = None
                fn.argtypes = []
                fn()
            except Exception as e:
                print(f"[scan_section] {call_before}() failed: {e}")

        # Find the target section
        section = next((s for s in self.pe.sections
                        if s["name"].rstrip("\x00") == section_name), None)
        if section is None:
            print(f"[scan_section] section {section_name!r} not found in PE")
            return {}

        load_base    = self.dll._handle
        runtime_base = load_base + section["vrva"]
        size         = section["vsize"]

        results: dict[int, dict] = {}
        try:
            raw = (ctypes.c_uint8 * size).from_address(runtime_base)
        except OSError:
            return {}

        for off in range(0, size - 7, 8):
            val = int.from_bytes(bytes(raw[off:off + 8]), "little")
            if not self._in_dll_exec(val):
                continue
            gva  = self._to_ghidra(val)
            fn   = self._fn_at(gva)
            name = fn["name"] if fn else f"FUN_{gva:#x}"
            results[off] = {"runtime": val, "ghidra_va": gva, "name": name,
                            "section": section_name, "section_offset": off}
            if len(results) >= max_results:
                break

        return results

    def scan_heap_for_fptrs(
        self,
        call_before: str | None = None,
        min_cluster: int = 3,
        max_regions: int = 500,
    ) -> dict[int, list[dict]]:
        """
        Scan all MEM_PRIVATE heap regions for clusters of in-DLL function pointers.

        This finds dispatch tables that were heap-allocated at runtime (malloc'd
        GBA state structs, C++ objects, etc.) — invisible to section scanning.

        call_before: export to call before scanning (e.g. retro_init).
        min_cluster: minimum consecutive fn ptrs to qualify as a dispatch table.

        Returns {region_base: [{"offset", "runtime", "ghidra_va", "name"}]}
        where each entry is a cluster of at least min_cluster fn ptrs.
        """
        import sys
        if sys.platform != "win32":
            return {}

        if call_before:
            try:
                fn = getattr(self.dll, call_before)
                fn.restype = None; fn.argtypes = []
                fn()
            except Exception as e:
                print(f"[heap_scan] {call_before}() failed: {e}")

        k32 = ctypes.WinDLL("kernel32")

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [("BaseAddress", ctypes.c_void_p),
                        ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", ctypes.c_ulong),
                        ("RegionSize", ctypes.c_size_t),
                        ("State", ctypes.c_ulong),
                        ("Protect", ctypes.c_ulong),
                        ("Type", ctypes.c_ulong)]

        MEM_COMMIT   = 0x1000
        MEM_PRIVATE  = 0x20000
        PAGE_GUARD   = 0x100
        PAGE_NOACCESS = 0x01
        # Only read from these protections (exclude guard/noaccess/execute-only)
        READABLE_PROT = {0x02, 0x04, 0x20, 0x40}  # RO, RW, EXEC_RO, EXEC_RW

        results: dict[int, list[dict]] = {}
        addr = 0
        n_regions = 0

        while n_regions < max_regions:
            mbi = MEMORY_BASIC_INFORMATION()
            ret = k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi),
                                   ctypes.sizeof(mbi))
            if ret == 0:
                break
            next_addr = (mbi.BaseAddress or 0) + mbi.RegionSize
            if next_addr <= addr:
                break

            base_prot = mbi.Protect & ~PAGE_GUARD  # strip guard flag
            is_readable = (mbi.State == MEM_COMMIT and
                           mbi.Type == MEM_PRIVATE and
                           mbi.RegionSize >= 64 and
                           not (mbi.Protect & PAGE_GUARD) and
                           base_prot in READABLE_PROT)

            if is_readable:
                n_regions += 1
                cluster: list[dict] = []
                base = mbi.BaseAddress or 0
                size = min(mbi.RegionSize, 0x400000)  # cap at 4MB per region

                # Read in 4KB chunks — safer than one large from_address
                for chunk_off in range(0, size, 0x1000):
                    chunk_size = min(0x1000, size - chunk_off)
                    try:
                        chunk = (ctypes.c_uint8 * chunk_size).from_address(
                            base + chunk_off)
                        raw = bytes(chunk)
                    except OSError:
                        if cluster and len(cluster) >= min_cluster:
                            results[base + cluster[0]["offset"]] = list(cluster)
                        cluster = []
                        continue

                    for i in range(0, chunk_size - 7, 8):
                        val = int.from_bytes(raw[i:i+8], "little")
                        off = chunk_off + i
                        if self._in_dll_exec(val):
                            gva  = self._to_ghidra(val)
                            fn   = self._fn_at(gva)
                            name = fn["name"] if fn else f"FUN_{gva:#x}"
                            cluster.append({"offset": off, "runtime": val,
                                            "ghidra_va": gva, "name": name})
                        elif cluster:
                            if len(cluster) >= min_cluster:
                                results[base + cluster[0]["offset"]] = list(cluster)
                            cluster = []

                if cluster and len(cluster) >= min_cluster:
                    results[base + cluster[0]["offset"]] = list(cluster)

            addr = next_addr

        return results

    def print_heap_fptrs(self, clusters: dict[int, list[dict]], top_clusters: int = 10) -> None:
        total = sum(len(v) for v in clusters.values())
        named = sum(1 for v in clusters.values()
                    for e in v if not e["name"].startswith("FUN_"))
        print(f"\nHEAP SCAN: {len(clusters)} clusters, {total} fn ptrs"
              f"  ({named} named, {total-named} unnamed)")
        shown = 0
        for base, entries in sorted(clusters.items(),
                                    key=lambda x: -len(x[1]))[:top_clusters]:
            print(f"\n  Cluster @ {base:#x}  ({len(entries)} fn ptrs):")
            for e in entries[:8]:
                print(f"    +{e['offset']:#06x}  {e['ghidra_va']:#014x}  {e['name']}")
            if len(entries) > 8:
                print(f"    ... and {len(entries)-8} more")
            shown += 1

    def print_section_fptrs(self, fptrs: dict[int, dict], top: int = 40) -> None:
        named = {k: v for k, v in fptrs.items() if not v["name"].startswith("FUN_")}
        unnamed = {k: v for k, v in fptrs.items() if v["name"].startswith("FUN_")}
        print(f"\nSECTION SCAN: {len(fptrs)} fn ptrs found"
              f"  ({len(named)} named, {len(unnamed)} unnamed)")
        shown = 0
        for off, info in sorted(fptrs.items()):
            if shown >= top:
                print(f"  ... and {len(fptrs)-top} more")
                break
            print(f"  +{off:#06x}  {info['ghidra_va']:#014x}  {info['name']}")
            shown += 1

    # ── vtable method caller ──────────────────────────────────────────────────

    def call_vtable_slot(self, obj_ptr: int, slot_idx: int,
                         argtypes: list | None = None,
                         args: list | None = None,
                         restype=None) -> int:
        """
        Call vtable slot <slot_idx> on a COM object at runtime address <obj_ptr>.
        COM calling convention: 'this' is always the first argument.
        Returns the integer return value (HRESULT or pointer).
        """
        if restype is None:
            restype = ctypes.c_long
        argtypes = argtypes or []
        args     = args or []

        vtbl_ptr = ctypes.c_uint64.from_address(obj_ptr).value
        fn_ptr   = ctypes.c_uint64.from_address(vtbl_ptr + slot_idx * 8).value
        fn_type  = ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)
        return fn_type(fn_ptr)(obj_ptr, *args)

    def release_com_object(self, obj_ptr: int) -> None:
        """Call IUnknown::Release (slot 2) on a COM object."""
        try:
            self.call_vtable_slot(obj_ptr, 2)
        except Exception:
            pass

    def _slot_by_name(self, slots: dict[int, dict], fragment: str,
                      exclude: str | None = None) -> int | None:
        """Find the first slot whose name contains <fragment>."""
        for i, info in sorted(slots.items()):
            name = info["name"]
            if fragment in name and (exclude is None or exclude not in name):
                return i
        return None

    # ── COM factory caller ────────────────────────────────────────────────────

    def _call_factory_raw(self, export_name: str, iid_string: str) -> int:
        """Call factory, return raw object pointer (caller must Release)."""
        try:
            fn = getattr(self.dll, export_name)
        except AttributeError:
            raise ValueError(f"Export not found: {export_name!r}")
        fn.restype  = ctypes.c_long
        fn.argtypes = [ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)]
        iid = GUID.from_string(iid_string)
        obj = ctypes.c_void_p(0)
        hr  = fn(ctypes.byref(iid), ctypes.byref(obj))
        if hr != 0 or not obj.value:
            raise RuntimeError(f"{export_name} failed: HRESULT={hr:#010x}")
        return obj.value

    def call_com_factory(self, export_name: str, iid_string: str,
                         max_slots: int = 64) -> dict[int, dict]:
        """
        Call a COM factory export with signature:
            HRESULT factory(REFIID riid, void **ppObject)
        Return the vtable slot map from the produced object.
        """
        obj_ptr = self._call_factory_raw(export_name, iid_string)
        slots   = self.walk_vtable(obj_ptr, max_slots)
        self.release_com_object(obj_ptr)
        return slots

    def walk_chain(self, chain_spec: list[dict],
                   max_slots: int = 64) -> dict[str, dict[int, dict]]:
        """
        Walk a chain of COM interfaces, scanning a vtable at each step.

        chain_spec is a list of steps. Each step is one of:

          Factory step (first step):
            {"type": "factory", "export": "CreateDXGIFactory",
             "iid": "{...}", "name": "IDXGIFactory"}

          Method step (subsequent steps):
            {"type": "method", "method": "EnumAdapters", "name": "IDXGIAdapter",
             "argtypes": [ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)],
             "args_fn": lambda out: [0, ctypes.byref(out)]}
            # args_fn receives the output ctypes.c_void_p and returns arg list

        Returns {interface_name: {slot_idx: slot_info}}.
        """
        results: dict[str, dict[int, dict]] = {}
        obj_stack: list[int] = []   # stack of live COM object pointers to Release

        def _get_current() -> int | None:
            return obj_stack[-1] if obj_stack else None

        for step in chain_spec:
            kind = step["type"]
            name = step["name"]

            if kind == "factory":
                try:
                    ptr = self._call_factory_raw(step["export"], step["iid"])
                except Exception as e:
                    print(f"  [chain] {name}: factory failed — {e}")
                    break
                obj_stack.append(ptr)

            elif kind == "method":
                parent_ptr = _get_current()
                if not parent_ptr:
                    break
                parent_slots = results.get(chain_spec[chain_spec.index(step) - 1]["name"], {})
                slot_idx = self._slot_by_name(parent_slots, step["method"])
                if slot_idx is None:
                    print(f"  [chain] {name}: method {step['method']!r} not found in parent vtable")
                    break
                out_ptr = ctypes.c_void_p(0)
                args_fn = step.get("args_fn", lambda o: [0, ctypes.byref(o)])
                try:
                    hr = self.call_vtable_slot(
                        parent_ptr, slot_idx,
                        argtypes=step.get("argtypes",
                                          [ctypes.c_uint32,
                                           ctypes.POINTER(ctypes.c_void_p)]),
                        args=args_fn(out_ptr),
                    )
                except Exception as e:
                    print(f"  [chain] {name}: call failed — {e}")
                    break
                if hr != 0 or not out_ptr.value:
                    print(f"  [chain] {name}: HRESULT={hr:#010x} ptr={out_ptr.value}")
                    break
                obj_stack.append(out_ptr.value)

            else:
                print(f"  [chain] unknown step type: {kind!r}")
                break

            slots = self.walk_vtable(_get_current(), max_slots)
            results[name] = slots
            print(f"  [chain] {name}: {len(slots)} slots")

        for ptr in reversed(obj_stack):
            self.release_com_object(ptr)

        return results

    # ── detection ─────────────────────────────────────────────────────────────

    def detect_vtable_users(self) -> list[str]:
        """
        Scan calltree for functions that use virtual dispatch (guard_dispatch_icall
        in callee list, or double-deref patterns in pseudocode).
        Returns list of function names.
        """
        hits = []
        for fn in self.calltree["functions"]:
            callees = fn.get("named_callees", [])
            pcode   = fn.get("pseudocode", "") or ""
            if (any("guard_dispatch_icall" in c for c in callees)
                    or "(**(code" in pcode
                    or "(*(code **)" in pcode):
                hits.append(fn["name"])
        return hits

    # ── KB emission ───────────────────────────────────────────────────────────

    def emit_to_kb(self, interface_name: str, slots: dict[int, dict]) -> int:
        """Emit vtable slot → VA mappings to knowledge bus. Returns count emitted."""
        try:
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from knowledge_bus import emit_discovery
        except ImportError:
            print("[vtable] knowledge_bus not available — skipping KB emit")
            return 0

        for slot_idx, info in slots.items():
            emit_discovery("vtable", "vtable_slot", {
                "interface":  interface_name,
                "slot":       slot_idx,
                "ghidra_va":  hex(info["ghidra_va"]),
                "name":       info["name"],
            })
        return len(slots)

    # ── reporting ─────────────────────────────────────────────────────────────

    def print_slots(self, interface_name: str, slots: dict[int, dict]) -> None:
        print(f"\nVTABLE: {interface_name}  ({len(slots)} slots resolved)")
        print(f"  {'SLOT':>4}  {'GHIDRA_VA':<14}  NAME")
        print(f"  {'-'*4}  {'-'*14}  {'-'*50}")
        for i, info in sorted(slots.items()):
            print(f"  [{i:2d}]  {info['ghidra_va']:#014x}  {info['name']}")


# ── Built-in chain specs ──────────────────────────────────────────────────────

DXGI_CHAIN = [
    {"type": "factory", "export": "CreateDXGIFactory",
     "iid": "{7b7166ec-21c7-44ae-b21a-c9ae321ae369}", "name": "IDXGIFactory"},
    {"type": "method",  "method": "EnumAdapters", "name": "IDXGIAdapter",
     "argtypes": [ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)],
     "args_fn": lambda out: [ctypes.c_uint32(0), ctypes.byref(out)]},
    {"type": "method",  "method": "EnumOutputs",  "name": "IDXGIOutput",
     "argtypes": [ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)],
     "args_fn": lambda out: [ctypes.c_uint32(0), ctypes.byref(out)]},
]

DXGI_FACTORY2_CHAIN = [
    {"type": "factory", "export": "CreateDXGIFactory2",
     "iid": "{50c83a1c-e072-4c48-87b0-3630fa36a6d0}", "name": "IDXGIFactory2",
     # CreateDXGIFactory2(Flags, REFIID, ppFactory) — different signature
    },
]

KNOWN_CHAINS: dict[str, list[dict]] = {
    "dxgi": DXGI_CHAIN,
}


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Dynamic COM vtable resolver")
    ap.add_argument("--calltree", required=True, help="Path to calltree.json")
    ap.add_argument("--dll",      required=True, help="Path to DLL")
    ap.add_argument("--export",   help="Factory export name (COM HRESULT factory)")
    ap.add_argument("--iid",      help='Interface IID e.g. "{7b7166ec-...}"')
    ap.add_argument("--name",     default="Interface", help="Interface name for KB/output")
    ap.add_argument("--max-slots", type=int, default=64)
    ap.add_argument("--detect",     action="store_true", help="List functions using vtable dispatch")
    ap.add_argument("--walk-chain", metavar="CHAIN",
                    help=f"Walk a built-in chain spec ({', '.join(KNOWN_CHAINS)})")
    ap.add_argument("--no-kb",      action="store_true", help="Skip KB emission")
    args = ap.parse_args()

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    r = VTableResolver(args.dll, args.calltree)

    if args.detect:
        users = r.detect_vtable_users()
        print(f"Functions using vtable dispatch: {len(users)}")
        for name in users[:40]:
            print(f"  {name}")
        if len(users) > 40:
            print(f"  ... and {len(users)-40} more")
        return

    if args.walk_chain:
        chain = KNOWN_CHAINS.get(args.walk_chain)
        if not chain:
            print(f"Unknown chain {args.walk_chain!r}. Available: {list(KNOWN_CHAINS)}")
            return
        all_results = r.walk_chain(chain, args.max_slots)
        total = 0
        for iface_name, slots in all_results.items():
            r.print_slots(iface_name, slots)
            if not args.no_kb:
                total += r.emit_to_kb(iface_name, slots)
        if not args.no_kb:
            print(f"\n[KB] emitted {total} vtable_slot observations total")
        return

    if not args.export:
        ap.error("--export required unless --detect or --walk-chain")
    if not args.iid:
        ap.error("--iid required for COM factory resolution")

    slots = r.call_com_factory(args.export, args.iid, args.max_slots)
    r.print_slots(args.name, slots)

    if not args.no_kb:
        n = r.emit_to_kb(args.name, slots)
        print(f"\n[KB] emitted {n} vtable_slot observations (layer=vtable)")


if __name__ == "__main__":
    main()
