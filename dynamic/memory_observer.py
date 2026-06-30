"""
dynamic/memory_observer.py — Observe memory state changes caused by calling a function.

For stateful functions (class=stateful from classify.run()), this module answers:
  "What global memory did this call mutate, and from what value to what value?"

That converts the dead-end "stateful — look at static analysis" hint into:
  MEMORY_TRACE: fsm_connect_test
    [0x7ffd4512+0x40]: 0x00000000 → 0x00000001  (10/10 calls, INVARIANT)
    [0x7ffd4512+0x44]: unchanged

Which is a concrete state transition the LLM can reason about without pseudocode.

HOW IT WORKS
------------
1. Snapshot all writable PE sections (.data, writable .bss) of the loaded DLL.
2. Call the function N times, taking a snapshot after each call.
3. Diff snapshots: find addresses that changed.
4. Aggregate across N calls: addresses that change consistently are INVARIANT transitions.
5. Emit invariant transitions to knowledge_bus as "memory_state_change" observations.

CLI
---
    py -3.13 re_toolkit/dynamic/memory_observer.py --dll <path> --func <name> [--n 10]
"""
from __future__ import annotations
import ctypes, os, sys, json, argparse
from dataclasses import dataclass

_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(_here)
sys.path.insert(0, _root)

from dynamic.execute import DLLExecutor, ExecuteResult
from pe_utils import PE


# PE section characteristic flags
_SECT_MEM_WRITE = 0x80000000
_SECT_CNT_UNINIT = 0x00000080   # .bss
_SECT_CNT_INIT   = 0x00000040   # .data


@dataclass
class StateTransition:
    """One memory address that changed across observed calls."""
    va: int              # absolute VA in loaded process
    rva: int             # RVA from DLL image base
    section: str         # section name (.data, .bss, ...)
    offset_in_section: int
    values_seen: list    # list of (before, after) tuples per call
    n_calls_total: int   # total calls observed (for consistent calculation)
    consistent: bool     # True if EVERY call showed the same before→after transition
    before_modal: int    # most common "before" value
    after_modal: int     # most common "after" value

    def as_hex(self, v: int) -> str:
        return f"0x{v & 0xFFFFFFFFFFFFFFFF:016x}"

    def to_dict(self) -> dict:
        return {
            "va":                 hex(self.va),
            "rva":                hex(self.rva),
            "section":            self.section,
            "offset_in_section":  hex(self.offset_in_section),
            "consistent":         self.consistent,
            "before":             self.as_hex(self.before_modal),
            "after":              self.as_hex(self.after_modal),
            "n_calls_changed":    len(self.values_seen),
        }


class MemoryObserver:
    """
    Observe which DLL globals a function mutates.

    Usage:
        ex  = DLLExecutor("foo.dll")
        obs = MemoryObserver(ex)
        transitions = obs.observe("my_func", n_calls=10)
        for t in transitions:
            print(t.to_dict())
    """

    def __init__(self, executor: DLLExecutor):
        self.executor   = executor
        self.load_base  = executor.load_base
        self.rebase     = executor.rebase
        self._sections  = self._writable_sections()

    def _writable_sections(self) -> list[dict]:
        """Return writable PE sections with their runtime VA ranges."""
        result = []
        for s in self.executor.pe.sections:
            chars = s.get("chars", 0)
            is_writable = bool(chars & _SECT_MEM_WRITE)
            # Accept any writable section; also accept .data/.bss by name as fallback
            # (some PE tools strip characteristics)
            by_name = s["name"] in (".data", ".bss", ".data1")
            if not (is_writable or by_name):
                continue
            size = max(s["vsize"], s["raw_size"])
            if size == 0:
                continue
            va_start = self.load_base + s["vrva"]
            result.append({
                "name":     s["name"],
                "va_start": va_start,
                "size":     size,
                "vrva":     s["vrva"],
            })
        return result

    def _snapshot(self) -> dict[int, bytes]:
        """Read current bytes from all writable sections. Returns {va_start: bytes}."""
        snap = {}
        for sect in self._sections:
            try:
                buf = (ctypes.c_uint8 * sect["size"])()
                ctypes.memmove(buf, sect["va_start"], sect["size"])
                snap[sect["va_start"]] = bytes(buf)
            except Exception:
                pass
        return snap

    def _diff(self, before: dict[int, bytes],
              after:  dict[int, bytes]) -> list[tuple[int, int, int]]:
        """
        Find bytes that changed between snapshots.
        Returns list of (absolute_va, old_val_u8, new_val_u8).
        Groups adjacent changed bytes into 8-byte aligned words.
        """
        changed = []
        for va_start, b_bytes in before.items():
            a_bytes = after.get(va_start)
            if not a_bytes:
                continue
            i = 0
            while i < len(b_bytes):
                if b_bytes[i] != a_bytes[i]:
                    # Align to 8-byte word
                    word_off = (i // 8) * 8
                    word_va  = va_start + word_off
                    end      = min(word_off + 8, len(b_bytes))
                    b_word   = int.from_bytes(b_bytes[word_off:end], "little")
                    a_word   = int.from_bytes(a_bytes[word_off:end], "little")
                    if b_word != a_word:
                        changed.append((word_va, b_word, a_word))
                    i = end   # skip to next word
                else:
                    i += 1
        return changed

    def _va_to_section(self, va: int) -> dict | None:
        for sect in self._sections:
            if sect["va_start"] <= va < sect["va_start"] + sect["size"]:
                return sect
        return None

    def observe(
        self,
        func:         int | str,
        n_calls:      int  = 10,
        arg_types     = None,
        ret_type      = None,
        args:         list | None = None,
        reset_fn               = None,
    ) -> list[StateTransition]:
        """
        Call `func` n_calls times, snapshot writable memory before and after each.

        reset_fn: optional callable() to reset DLL state between calls
                  (e.g. call an init function so the FSM starts in the same state).
                  If None, state accumulates across calls — both modes are useful:
                    - accumulating: reveals sequential state machine transitions
                    - resetting:    reveals a single transition in isolation

        Returns list of StateTransition for addresses that changed in >= 1 call.
        """
        call_args  = args or []
        changes_by_va: dict[int, list[tuple[int, int]]] = {}

        for _ in range(n_calls):
            if reset_fn is not None:
                try:
                    reset_fn()
                except Exception:
                    pass

            before = self._snapshot()

            if isinstance(func, int):
                self.executor.call_va(func, call_args, arg_types, ret_type)
            else:
                self.executor.call_export(func, call_args, arg_types, ret_type)

            after = self._snapshot()

            for va, old, new in self._diff(before, after):
                changes_by_va.setdefault(va, []).append((old, new))

        # Build StateTransition objects
        transitions = []
        for va, pairs in sorted(changes_by_va.items()):
            sect = self._va_to_section(va)
            if sect is None:
                continue
            befores = [p[0] for p in pairs]
            afters  = [p[1] for p in pairs]
            modal_before = max(set(befores), key=befores.count)
            modal_after  = max(set(afters),  key=afters.count)
            # consistent = EVERY call showed the same transition (not just the ones that changed)
            consistent = (len(pairs) == n_calls
                          and len(set(afters)) == 1
                          and len(set(befores)) == 1)
            off_in_sect = va - sect["va_start"]
            transitions.append(StateTransition(
                va                = va,
                rva               = sect["vrva"] + off_in_sect,   # Ghidra-stable: image_base + rva = Ghidra VA
                section           = sect["name"],
                offset_in_section = off_in_sect,
                values_seen       = pairs,
                n_calls_total     = n_calls,
                consistent        = consistent,
                before_modal      = modal_before,
                after_modal       = modal_after,
            ))
        return transitions

    def llm_hint(self, func_id: str, transitions: list[StateTransition],
                 n_calls: int) -> str:
        """Build an LLM-ready hint string from observed transitions."""
        if not transitions:
            return (f"MEMORY_TRACE: {func_id} — no writable-global mutations observed "
                    f"in {n_calls} calls. Function may write only to stack or heap.")

        lines = [f"MEMORY_TRACE: {func_id} ({n_calls} calls observed)"]
        invariant = [t for t in transitions if t.consistent]
        variable  = [t for t in transitions if not t.consistent]

        if invariant:
            lines.append(f"  INVARIANT transitions ({len(invariant)} address(es)):")
            for t in invariant[:8]:
                lines.append(
                    f"    [{t.section}+0x{t.offset_in_section:x}]  "
                    f"{t.as_hex(t.before_modal)} → {t.as_hex(t.after_modal)}  "
                    f"(every call)"
                )
        if variable:
            lines.append(f"  VARIABLE transitions ({len(variable)} address(es) — state accumulates):")
            for t in variable[:4]:
                sample = t.values_seen[:3]
                sample_str = "  ".join(
                    f"{t.as_hex(b)}→{t.as_hex(a)}" for b, a in sample
                )
                lines.append(
                    f"    [{t.section}+0x{t.offset_in_section:x}]  {sample_str}..."
                )

        lines.append(
            "  These are confirmed global state mutations — the addresses above carry "
            "the function's side-effect state. Cross-reference with pseudocode to name fields."
        )
        return "\n".join(lines)

    def emit_to_kb(self, func_id: str, transitions: list[StateTransition],
                   layer: str = "dynamic") -> None:
        """
        Emit invariant transitions to knowledge_bus as memory_state_change observations.

        Stores Ghidra-stable address: image_base + rva (NOT runtime absolute VA).
        This is the VA Ghidra would show for the global (e.g. DAT_0001074a0).
        Convert back to runtime VA: ghidra_va + executor.rebase.
        """
        image_base = self.executor.pe.image_base
        try:
            sys.path.insert(0, _root)
            from knowledge_bus import emit_discovery
            for t in transitions:
                ghidra_va = image_base + t.rva   # stable across DLL reloads
                emit_discovery(layer, "memory_state_change", {
                    "func_id":    func_id,
                    "ghidra_va":  hex(ghidra_va),   # image_base + rva — use in Ghidra
                    "section":    t.section,
                    "offset":     hex(t.offset_in_section),
                    "rva":        hex(t.rva),
                    "before":     t.as_hex(t.before_modal),
                    "after":      t.as_hex(t.after_modal),
                    "n_observed": t.n_calls_total,
                    "n_changed":  len(t.values_seen),
                    "consistent": t.consistent,
                })
        except Exception:
            pass


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Observe memory state changes caused by a DLL function")
    ap.add_argument("--dll",  required=True)
    ap.add_argument("--func", required=True, help="Export name or 0xVA")
    ap.add_argument("--n",    type=int, default=10, help="Number of calls (default 10)")
    ap.add_argument("--emit", action="store_true", help="Emit invariants to knowledge_bus")
    opts = ap.parse_args()

    ex   = DLLExecutor(opts.dll)
    func = int(opts.func, 16) if opts.func.startswith("0x") else opts.func
    obs  = MemoryObserver(ex)

    print(f"Writable sections: {[s['name'] for s in obs._sections]}")
    print(f"Calling {opts.func} × {opts.n}...")
    transitions = obs.observe(func, n_calls=opts.n)

    if not transitions:
        print("No global memory mutations observed.")
    else:
        print(f"\n{len(transitions)} address(es) changed:")
        for t in transitions:
            print(json.dumps(t.to_dict(), indent=2))

    hint = obs.llm_hint(str(func), transitions, opts.n)
    print(f"\n{hint}")

    if opts.emit and transitions:
        obs.emit_to_kb(str(func), transitions)
        print(f"\nEmitted {sum(1 for t in transitions if t.consistent)} invariant(s) to KB.")
