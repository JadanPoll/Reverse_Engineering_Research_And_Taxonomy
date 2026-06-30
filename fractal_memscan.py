"""
fractal_memscan.py — Adaptive hierarchical memory scanner.

Regions start in the slowest tier (wide blocks, long intervals).
When a region changes, it splits into sub-regions and those get
promoted to the next tier (tighter blocks, shorter interval).
Within those, further changes promote again — self-similar at every level.
Regions that stabilize demote back toward the cold tier.

Usage:
    python fractal_memscan.py --pid PID [options]
    python fractal_memscan.py --name Hss.Store.Client [options]
    python fractal_memscan.py --pid PID --filter-module Hss.Store.Client.dll

Options:
    --pid PID               Target process PID
    --name SUBSTR           Attach to first process whose name contains SUBSTR
    --filter-module NAME    Only track memory belonging to this module
    --filter-addr ADDR      Only track regions containing this address (hex)
    --min-tier INT          Start monitoring from this tier (0=coldest, default 0)
    --show-stable           Also print regions that were promoted but stabilized
    --decode                Try to decode changed bytes as strings
"""

import sys, os, time, struct, ctypes, ctypes.wintypes, heapq, hashlib, argparse, re
from collections import defaultdict
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Win32 memory API ──────────────────────────────────────────────────────────

k32 = ctypes.WinDLL("kernel32.dll")

PROCESS_VM_READ           = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT   = 0x1000
MEM_PRIVATE  = 0x20000
MEM_MAPPED   = 0x40000
MEM_IMAGE    = 0x1000000
PAGE_NOACCESS = 0x01
PAGE_GUARD    = 0x100
PAGE_NOCACHE  = 0x200
PAGE_WRITECOMBINE = 0x400

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_uint64),
        ("AllocationBase",    ctypes.c_uint64),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("__alignment1",      ctypes.wintypes.DWORD),
        ("RegionSize",        ctypes.c_uint64),
        ("State",             ctypes.wintypes.DWORD),
        ("Protect",           ctypes.wintypes.DWORD),
        ("Type",              ctypes.wintypes.DWORD),
        ("__alignment2",      ctypes.wintypes.DWORD),
    ]

TH32CS_SNAPMODULE   = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize",        ctypes.wintypes.DWORD),
        ("th32ModuleID",  ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("GlblcntUsage",  ctypes.wintypes.DWORD),
        ("ProccntUsage",  ctypes.wintypes.DWORD),
        ("modBaseAddr",   ctypes.c_uint64),
        ("modBaseSize",   ctypes.wintypes.DWORD),
        ("hModule",       ctypes.c_uint64),
        ("szModule",      ctypes.c_wchar * 256),
        ("szExePath",     ctypes.c_wchar * 260),
    ]

def open_process(pid):
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        raise OSError(f"OpenProcess({pid}) failed: {ctypes.GetLastError()}")
    return h

def read_mem(hproc, addr, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(hproc, ctypes.c_uint64(addr),
                               buf, size, ctypes.byref(read))
    if not ok or read.value == 0:
        return None
    return bytes(buf[:read.value])

def enum_memory(hproc):
    """Yield (base, size, protect, type) for all committed readable regions."""
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    bad_protect = PAGE_NOACCESS | PAGE_GUARD
    while True:
        ret = k32.VirtualQueryEx(hproc, ctypes.c_uint64(addr),
                                 ctypes.byref(mbi), ctypes.sizeof(mbi))
        if ret == 0:
            break
        if (mbi.State == MEM_COMMIT and
                not (mbi.Protect & bad_protect) and
                mbi.Protect != 0):
            yield mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type
        addr = mbi.BaseAddress + mbi.RegionSize
        if addr >= 0x7FFFFFFFFFFF:
            break

def get_modules(pid):
    """Return dict of module_name_lower → (base, size)."""
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == ctypes.c_void_p(-1).value or snap == 0:
        return {}
    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(MODULEENTRY32W)
    modules = {}
    try:
        if k32.Module32FirstW(snap, ctypes.byref(me)):
            while True:
                modules[me.szModule.lower()] = (me.modBaseAddr, me.modBaseSize)
                if not k32.Module32NextW(snap, ctypes.byref(me)):
                    break
    finally:
        k32.CloseHandle(snap)
    return modules

def find_pid_by_name(substr):
    TH32CS_SNAPPROCESS = 0x00000002
    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize",              ctypes.wintypes.DWORD),
            ("cntUsage",            ctypes.wintypes.DWORD),
            ("th32ProcessID",       ctypes.wintypes.DWORD),
            ("th32DefaultHeapID",   ctypes.c_uint64),
            ("th32ModuleID",        ctypes.wintypes.DWORD),
            ("cntThreads",          ctypes.wintypes.DWORD),
            ("th32ParentProcessID", ctypes.wintypes.DWORD),
            ("pcPriClassBase",      ctypes.c_long),
            ("dwFlags",             ctypes.wintypes.DWORD),
            ("szExeFile",           ctypes.c_wchar * 260),
        ]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    results = []
    if k32.Process32FirstW(snap, ctypes.byref(pe)):
        while True:
            if substr.lower() in pe.szExeFile.lower():
                results.append((pe.th32ProcessID, pe.szExeFile))
            if not k32.Process32NextW(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)
    return results

# ── Noise exclusions (always-changing system pages) ──────────────────────────
# KUSER_SHARED_DATA (0x7ffe0000): Windows clock/perf counters updated every 15ms.
# Mapped in every user-mode process. Pure noise — exclude by default.
EXCLUDE_RANGES = [
    (0x7ffe0000, 0x7fff0000),   # KUSER_SHARED_DATA
]

# ── Mathematical invariant (verify function) ──────────────────────────────────
#
# Imported from ground_truth.py (H=1 single source of truth).
# ground_truth.verify() is the oracle shared by all three analysis layers:
#   Ghidra (static), fractal_memscan (dynamic), runtime_probe (Frida live).
# A hit from any layer is definitive.

import sys as _sys, os as _os
_here = _os.path.dirname(_os.path.abspath(__file__))
if _here not in _sys.path:
    _sys.path.insert(0, _here)

try:
    from ground_truth import verify
    _HAS_VERIFY = True
except Exception:
    try:
        from Crypto.Cipher import AES as _AES
        def verify(key: bytes, iv: bytes) -> bool:
            return False  # no ground_truth.py — oracle disabled
        _HAS_VERIFY = False
    except ImportError:
        def verify(key: bytes, iv: bytes) -> bool:
            return False
        _HAS_VERIFY = False

try:
    from knowledge_bus import emit_verify_hit as _kb_emit_verify_hit
    _HAS_KB = True
except Exception:
    _HAS_KB = False
    def _kb_emit_verify_hit(*a, **kw): pass

try:
    from corpus_logger import (log_observation  as _corpus_log_obs,
                                log_verify_hit   as _corpus_log_hit,
                                begin_session    as _corpus_begin,
                                end_session      as _corpus_end)
    _HAS_CORPUS = True
except Exception:
    _HAS_CORPUS = False
    def _corpus_log_obs(*a, **kw): pass
    def _corpus_log_hit(*a, **kw): pass
    def _corpus_begin(*a, **kw): pass
    def _corpus_end(): pass

# Accumulates 16-byte candidate blocks seen in recent T2+ scans.
# When a new one arrives, checked against all others as (key, iv) pairs.
_candidate_pool: dict[int, bytes] = {}  # addr → 16 bytes

def _check_candidate(addr: int, data: bytes) -> bool:
    """
    Check a 16-byte block as potential key or IV.
    Returns True and prints a discovery if verify() hits.
    """
    if not _HAS_VERIFY or len(data) < 16:
        return False
    for i in range(0, len(data) - 15, 16):
        candidate = data[i:i+16]
        if candidate == b'\x00' * 16:
            continue
        _candidate_pool[addr + i] = candidate
        # Try this as K, all pooled as IV
        for iv_addr, iv in list(_candidate_pool.items()):
            if iv_addr == addr + i:
                continue
            if verify(candidate, iv):
                print(f"\n{'!'*70}")
                print(f"  VERIFY HIT: K @ 0x{addr+i:016x}  IV @ 0x{iv_addr:016x}")
                print(f"  K  = {candidate.hex()}")
                print(f"  IV = {iv.hex()}")
                print(f"{'!'*70}\n")
                _kb_emit_verify_hit("memscan", candidate.hex(), iv.hex(),
                                    va_hint=addr+i,
                                    context={"k_addr": hex(addr+i), "iv_addr": hex(iv_addr)})
                return True
            if verify(iv, candidate):
                print(f"\n{'!'*70}")
                print(f"  VERIFY HIT: K @ 0x{iv_addr:016x}  IV @ 0x{addr+i:016x}")
                print(f"  K  = {iv.hex()}")
                print(f"  IV = {candidate.hex()}")
                print(f"{'!'*70}\n")
                _kb_emit_verify_hit("memscan", iv.hex(), candidate.hex(),
                                    va_hint=iv_addr,
                                    context={"k_addr": hex(iv_addr), "iv_addr": hex(addr+i)})
                return True
    return False

# ── Tier configuration ────────────────────────────────────────────────────────

# Each tier: (interval_seconds, block_size_bytes, label)
# block_size is the granularity at which this tier splits regions
TIERS = [
    (8.000, 65536,  "❄  cold"),    # T0: 64 KB, every  8s
    (2.000,  4096,  "○  warm"),    # T1:  4 KB, every  2s
    (0.400,   256,  "◑  hot "),    # T2: 256 B, every 0.4s
    (0.080,    32,  "●  burn"),    # T3:  32 B, every 80ms
    (0.016,    16,  "★  live"),    # T4:  16 B, every 16ms
]
MAX_TIER  = len(TIERS) - 1

PROMOTE_AFTER    = 2   # consecutive changes before promoting
DEMOTE_AFTER     = 15  # consecutive stable scans before demoting
THROTTLE_AFTER   = 3   # after this many changes to same node, switch to summary
THROTTLE_SUMMARY = 20  # print a throttle-summary every N suppressed changes
VERBOSE_TIER     = 2   # tiers < this show only summary lines (no byte diffs)

# ── RegionNode ────────────────────────────────────────────────────────────────

_node_counter = 0

class RegionNode:
    __slots__ = ('id', 'addr', 'size', 'tier', 'parent',
                 'children', 'last_data', 'last_hash',
                 'change_streak', 'stable_streak',
                 'next_scan', 'total_changes', 'suppressed')

    def __init__(self, addr, size, tier=0, parent=None):
        global _node_counter
        _node_counter += 1
        self.id             = _node_counter
        self.addr           = addr
        self.size           = size
        self.tier           = tier
        self.parent         = parent
        self.children       = []       # child nodes if promoted
        self.last_data      = None     # bytes snapshot (only at T2+)
        self.last_hash      = None     # hash of last scan
        self.change_streak  = 0
        self.stable_streak  = 0
        self.next_scan      = time.monotonic()
        self.total_changes  = 0
        self.suppressed     = 0   # changes suppressed by throttle

    def interval(self):
        return TIERS[self.tier][0]

    def child_block_size(self):
        return TIERS[min(self.tier + 1, MAX_TIER)][1]

    def tier_label(self):
        return TIERS[self.tier][2]

# ── Scanner ───────────────────────────────────────────────────────────────────

class FractalScanner:

    def __init__(self, pid, filter_ranges=None, decode=False, show_stable=False):
        self.pid          = pid
        self.hproc        = open_process(pid)
        self.filter       = filter_ranges  # list of (start, end) or None = all
        self.decode       = decode
        self.show_stable  = show_stable

        # heap entries: (next_scan_time, node_id)
        # nodes dict: id → RegionNode
        self._heap   = []
        self._nodes  = {}

        # stats
        self.scans_done   = 0
        self.changes_seen = 0
        self.start_time   = time.monotonic()

    def close(self):
        if self.hproc:
            k32.CloseHandle(self.hproc)
            self.hproc = None

    # ── Setup ────────────────────────────────────────────────────────────────

    def seed(self):
        """Enumerate all readable memory regions and add as T0 nodes."""
        count = 0
        for base, size, protect, mtype in enum_memory(self.hproc):
            # Skip known-noisy system pages
            end = base + size
            if any(ex_s < end and base < ex_e for ex_s, ex_e in EXCLUDE_RANGES):
                continue

            # Apply address filter if set
            if self.filter:
                overlaps = any(start <= base < end or base <= start < base+size
                               for start, end in self.filter)
                if not overlaps:
                    continue

            # Split large regions into 64 KB T0 blocks from the start
            block = TIERS[0][1]  # 64 KB
            for off in range(0, size, block):
                baddr = base + off
                bsize = min(block, size - off)
                # Also skip individual blocks that land in excluded ranges
                if any(ex_s <= baddr < ex_e for ex_s, ex_e in EXCLUDE_RANGES):
                    continue
                node = RegionNode(baddr, bsize, tier=0)
                self._add_node(node)
                count += 1

        print(f"[seed] {count} T0 regions across {self._total_bytes()//1024:,} KB of "
              f"filtered address space", flush=True)

    def _total_bytes(self):
        return sum(n.size for n in self._nodes.values() if not n.children)

    def _add_node(self, node):
        self._nodes[node.id] = node
        heapq.heappush(self._heap, (node.next_scan, node.id))

    def _remove_node(self, node):
        # Mark as removed; heap entries are lazy-deleted
        self._nodes.pop(node.id, None)

    # ── Main loop ────────────────────────────────────────────────────────────

    def run(self, duration=None):
        end_time = (time.monotonic() + duration) if duration else None
        last_stat = time.monotonic()

        while True:
            now = time.monotonic()
            if end_time and now >= end_time:
                break

            # Process all nodes whose scan time is due
            processed = 0
            while self._heap:
                nxt, nid = self._heap[0]
                if nxt > now + 0.001:
                    break
                heapq.heappop(self._heap)
                node = self._nodes.get(nid)
                if node is None:
                    continue  # lazy-deleted
                if node.children:
                    continue  # has children — scan them instead
                self._scan_node(node)
                processed += 1

            # Print stats every 5s
            if now - last_stat >= 5.0:
                self._print_stats()
                last_stat = now

            # Sleep until next due scan (min 1ms)
            next_wake = 0.001
            if self._heap:
                nxt, _ = self._heap[0]
                next_wake = max(0.001, min(0.1, nxt - time.monotonic()))
            time.sleep(next_wake)

    # ── Scan a single leaf node ───────────────────────────────────────────────

    def _scan_node(self, node):
        self.scans_done += 1
        data = read_mem(self.hproc, node.addr, node.size)

        if data is None:
            # Region no longer readable — retire it
            self._remove_node(node)
            return

        # Hash for fast comparison (MD5 is fast enough for <64KB blocks)
        h = hashlib.md5(data).digest()
        changed = (h != node.last_hash)

        first_read = (node.last_hash is None)

        if changed and not first_read:
            node.change_streak += 1
            node.stable_streak  = 0
            node.total_changes += 1
            self.changes_seen  += 1

            self._report_change(node, data)

            # Promote if we hit the streak threshold
            if node.change_streak >= PROMOTE_AFTER and node.tier < MAX_TIER:
                self._promote(node)
                return  # promoted — children will be scanned

        elif first_read:
            pass  # baseline — no streak counting, no reporting

        else:
            node.stable_streak += 1
            node.change_streak  = 0

        node.last_hash = h
        # Store full bytes at T2+ for detailed diffing; at T0/T1 only the hash
        node.last_data = data if node.tier >= VERBOSE_TIER else None

        if not changed and not first_read:
            # Demote if very stable (but only if above T0)
            if node.stable_streak >= DEMOTE_AFTER and node.tier > 0:
                self._demote(node)
                return

        # Reschedule
        node.next_scan = time.monotonic() + node.interval()
        heapq.heappush(self._heap, (node.next_scan, node.id))

    # ── Promotion / Demotion ─────────────────────────────────────────────────

    def _promote(self, node):
        child_tier  = min(node.tier + 1, MAX_TIER)
        child_block = TIERS[child_tier][1]
        count       = 0

        for off in range(0, node.size, child_block):
            caddr = node.addr + off
            csize = min(child_block, node.size - off)
            child = RegionNode(caddr, csize, tier=child_tier, parent=node)
            # Stagger first scans slightly to avoid burst
            child.next_scan = time.monotonic() + (off / node.size) * child.interval()
            node.children.append(child)
            self._add_node(child)
            count += 1

        t_old = TIERS[node.tier][2]
        t_new = TIERS[child_tier][2]
        print(f"\n[↑ PROMOTE] 0x{node.addr:016x} +{node.size:#x}  "
              f"{t_old} → {t_new}  ({count} children × {child_block}B)", flush=True)
        self._remove_node(node)

    def _demote(self, node):
        if self.show_stable:
            print(f"\n[↓ demote ] 0x{node.addr:016x} +{node.size:#x}  "
                  f"{node.tier_label()} → T{node.tier-1}", flush=True)
        parent = node.parent
        if parent and parent.id in self._nodes:
            # Remove all siblings, restore parent to scan list
            for sib in parent.children:
                self._remove_node(sib)
            parent.children.clear()
            parent.tier          = max(0, parent.tier - 1)
            parent.change_streak = 0
            parent.stable_streak = 0
            parent.last_hash     = None
            parent.next_scan     = time.monotonic() + parent.interval()
            heapq.heappush(self._heap, (parent.next_scan, parent.id))
        else:
            # No parent — just drop tier on this node
            node.tier          = max(0, node.tier - 1)
            node.stable_streak = 0
            node.next_scan     = time.monotonic() + node.interval()
            heapq.heappush(self._heap, (node.next_scan, node.id))

    # ── Change reporting ─────────────────────────────────────────────────────

    def _report_change(self, node, new_data):
        elapsed    = f"{time.monotonic() - self.start_time:8.2f}s"
        tier_label = node.tier_label()

        # Tiers below VERBOSE_TIER: one-liner summary, no byte diff (avoids flood)
        if node.tier < VERBOSE_TIER:
            # Only print when about to promote (reduces noise)
            if node.change_streak == PROMOTE_AFTER - 1:
                print(f"[{elapsed}] {tier_label}  "
                      f"0x{node.addr:016x}  size={node.size:#x}  "
                      f"[change #{node.total_changes} -- promoting next]", flush=True)
            return

        # Throttle verbose regions at T2+
        if node.total_changes > THROTTLE_AFTER:
            node.suppressed += 1
            if node.suppressed % THROTTLE_SUMMARY == 0:
                print(f"[{elapsed}] {tier_label}  "
                      f"0x{node.addr:016x}  "
                      f"[throttled: {node.total_changes} total, "
                      f"{node.suppressed} suppressed]", flush=True)
            return

        # Full byte diff at T2+
        old   = node.last_data or bytes(len(new_data))
        diffs = self._diff_ranges(old, new_data)

        for d_off, d_len in diffs:
            addr = node.addr + d_off
            ob   = old[d_off:d_off+d_len]
            nb   = new_data[d_off:d_off+d_len]
            oh   = ob.hex().upper()
            nh   = nb.hex().upper()

            decode_str = ""
            if self.decode:
                for enc in ("utf-16-le", "utf-8", "latin-1"):
                    try:
                        s = nb.decode(enc).strip("\x00").strip()
                        if len(s) >= 4 and all(0x20 <= ord(c) <= 0x7e for c in s[:20]):
                            decode_str = f"  -> {s[:60]!r}"
                            break
                    except Exception:
                        pass

            ellipsis = "..." if len(oh) > 32 else ""
            print(f"[{elapsed}] {tier_label}  "
                  f"0x{addr:016x} +{d_off:#05x} [{d_len:3d}B]  "
                  f"{oh[:32]}{ellipsis}  ->  "
                  f"{nh[:32]}{'...' if len(nh)>32 else ''}"
                  f"{decode_str}", flush=True)

            # Invariant check: any new 16-byte aligned block could be K or IV
            _check_candidate(addr, nb)

            # Corpus: log ALL 16-byte-aligned blocks — not just verify() hits.
            # The rare signal (UNKNOWN_INVARIANT) lives in blocks that never fire
            # verify() but are INVARIANT across sessions. corpus_analyze.py finds them.
            if _HAS_CORPUS and len(nb) >= 16:
                for i in range(0, len(nb) - 15, 16):
                    blk = nb[i:i+16]
                    if blk != b'\x00' * 16:
                        _corpus_log_obs(addr + i, blk, tier=node.tier)

    @staticmethod
    def _diff_ranges(a, b, merge_gap=8):
        """Return list of (offset, length) for changed byte runs, gaps <= merge_gap merged."""
        sz   = min(len(a), len(b))
        runs = []
        i    = 0
        while i < sz:
            if a[i] != b[i]:
                j = i + 1
                while j < sz and b[j] != a[j]:
                    j += 1
                runs.append((i, j - i))
                i = j
            else:
                i += 1

        if len(b) > len(a):
            runs.append((len(a), len(b) - len(a)))

        # Merge runs separated by small gaps
        if len(runs) <= 1:
            return runs
        merged = [runs[0]]
        for start, length in runs[1:]:
            p_start, p_len = merged[-1]
            if start - (p_start + p_len) <= merge_gap:
                merged[-1] = (p_start, start + length - p_start)
            else:
                merged.append((start, length))
        return merged

    # ── Stats ─────────────────────────────────────────────────────────────────

    def _print_stats(self):
        tier_counts = defaultdict(int)
        for node in self._nodes.values():
            tier_counts[node.tier] += 1
        t_str = "  ".join(
            f"T{t}:{tier_counts[t]}" for t in sorted(tier_counts)
        )
        elapsed = time.monotonic() - self.start_time
        rate = self.scans_done / elapsed if elapsed > 0 else 0
        print(f"\n[STATS {elapsed:6.0f}s] nodes: {t_str}  "
              f"scans: {self.scans_done:,} ({rate:.0f}/s)  "
              f"changes: {self.changes_seen:,}", flush=True)

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid",           type=int,   help="Target PID")
    ap.add_argument("--name",          type=str,   help="Attach by process name substring")
    ap.add_argument("--filter-module", type=str,   help="Restrict to this module (e.g. Hss.Store.Client.dll)")
    ap.add_argument("--filter-addr",   type=str,   help="Restrict to region containing this hex address")
    ap.add_argument("--duration",      type=float, default=None, help="Run for N seconds then exit")
    ap.add_argument("--decode",        action="store_true", help="Decode changed bytes as strings")
    ap.add_argument("--show-stable",   action="store_true", help="Print demotion events")
    args = ap.parse_args()

    # Resolve PID
    pid = args.pid
    if not pid and args.name:
        matches = find_pid_by_name(args.name)
        if not matches:
            print(f"No process found matching {args.name!r}")
            sys.exit(1)
        if len(matches) > 1:
            print(f"Multiple matches:")
            for p, n in matches:
                print(f"  {p:6d}  {n}")
            sys.exit(1)
        pid, pname = matches[0]
        print(f"Found: {pname} (PID {pid})")
    if not pid:
        ap.print_help()
        sys.exit(1)

    # Build filter ranges
    filter_ranges = None
    if args.filter_module or args.filter_addr:
        mods = get_modules(pid)
        filter_ranges = []

        if args.filter_module:
            key = args.filter_module.lower()
            found = {k: v for k, v in mods.items() if key in k}
            if not found:
                print(f"Module {args.filter_module!r} not found. Available modules:")
                for k in sorted(mods):
                    b, s = mods[k]
                    print(f"  {k:60s}  base=0x{b:016x}  size={s//1024:,}KB")
                sys.exit(1)
            for k, (base, size) in found.items():
                print(f"Filtering to module: {k}  0x{base:016x} – 0x{base+size:016x}  ({size//1024:,} KB)")
                filter_ranges.append((base, base + size))

        if args.filter_addr:
            addr = int(args.filter_addr, 16)
            # Find the region containing this address
            hproc = open_process(pid)
            mbi   = MEMORY_BASIC_INFORMATION()
            if k32.VirtualQueryEx(hproc, ctypes.c_uint64(addr),
                                  ctypes.byref(mbi), ctypes.sizeof(mbi)):
                r = (mbi.BaseAddress, mbi.BaseAddress + mbi.RegionSize)
                print(f"Filtering to region containing 0x{addr:016x}: "
                      f"0x{r[0]:016x}–0x{r[1]:016x}")
                filter_ranges.append(r)
            k32.CloseHandle(hproc)

    scanner = FractalScanner(pid, filter_ranges=filter_ranges,
                             decode=args.decode, show_stable=args.show_stable)
    try:
        scanner.seed()
        print(f"Starting fractal scan (PID {pid}). "
              f"Tier intervals: "
              + "  ".join(f"T{i}={t[0]:.3f}s/{t[1]}B" for i, t in enumerate(TIERS))
              + "\n", flush=True)
        scanner.run(duration=args.duration)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        scanner._print_stats()
        scanner.close()

if __name__ == "__main__":
    main()
