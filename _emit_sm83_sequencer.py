"""
Emit SM83 instruction sequencer fields discovered from FUN_20c866a30.
This function is the complete SM83 CPU execution engine — confirmed all remaining
CPU state struct fields and the op_type dispatch model.
"""
import sys
sys.path.insert(0, r"C:\Users\nathan37\Desktop\re_toolkit")
from knowledge_bus import emit_field_access, emit_discovery

STRUCT_KEY = "mGBA_SM83State"
FUNC_VA    = "0x20c866a30"

fields = [
    (0x0d, "pc",               "case 3: *(param_1+0xd) += 1 after fetch — Program Counter"),
    (0x14, "cycle_cost",       "loop: elapsed += param_1[0x14] per step — T-state cost"),
    (0x18, "elapsed_cycles",   "loop condition: iVar5 = *(param_1+0x18)"),
    (0x1c, "cycle_budget",     "loop condition: iVar7 = *(param_1+0x1c)"),
    (0x20, "op_type",          "switch(uVar1=*(param_1+0x20)) — 3=fetch, 7=read, 0xB=write, 0=nop"),
    (0x30, "exec_mode_flag",   "case 3: if (*(char*)(param_1+0x30)==0) — controls fetch path"),
    (0x38, "memory_read_fn",   "case 3: (**(param_1+0x38))(param_1, PC) — fetch byte from memory"),
    (0x80, "frame_advance_fn", "called when elapsed>=budget: (**(param_1+0x80))(param_1)"),
]

print(f"Emitting {len(fields)} SM83 sequencer fields...")
for offset, name, evidence in fields:
    emit_field_access(
        struct_key=STRUCT_KEY, offset=offset, field_name=name,
        layer="ghidra", func_va=FUNC_VA, evidence=evidence,
    )
    print(f"  +{offset:#05x}  {name}")

# Op-type constants
emit_discovery("ghidra", "sm83_op_types", {
    "binary": "mgba_libretro.dll",
    "struct": "mGBA_SM83State offset +0x20",
    "values": {
        "0": "NOP / complete (null callback = FUN_20c860d50)",
        "3": "FETCH: read byte from PC, increment PC, opcode→+0x25, dispatch",
        "7": "MEM_READ: read from mem_addr(+0x10), result→+0x25, fire callback(+0x28)",
        "11": "MEM_WRITE: write +0x25 to mem_addr(+0x10), fire callback(+0x28)",
    },
})

# The op_type dispatch table
emit_discovery("ghidra", "sm83_optype_table", {
    "binary":    "mgba_libretro.dll",
    "table_va":  "PTR_FUN_20ca44c00",
    "size":      8,
    "entry_0":   "FUN_20c860d50 (null terminator — signals end of instruction)",
    "entry_1_7": "FUN_20c862c70..FUN_20c865db0 (op_type handlers 1-7)",
})

# Complete architecture summary
emit_discovery("ghidra", "sm83_architecture_summary", {
    "binary": "mgba_libretro.dll",
    "summary": (
        "SM83 CPU uses continuation-passing style (CPS) execution. "
        "Each instruction is a sequence of op_types (fetch→compute→writeback). "
        "op_type stored at +0x20, cleared each step. "
        "Continuation installed at +0x28. "
        "Memory access goes through +0x38 (read_fn) with result at +0x25. "
        "Cycle budget at +0x1c limits execution per retro_run call. "
        "HALT state: op_type==3 returns immediately without fetching. "
        "This architecture makes SM83 component a disconnected call graph island "
        "— all connections are via function pointers, invisible to static analysis."
    ),
})

print("\n[KB] Emitted op_type constants, dispatch table, and architecture summary")
print("Done. SM83 CPU fully mapped from static analysis.")
