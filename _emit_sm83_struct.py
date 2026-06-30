"""
Emit SM83/LR35902 CPU state struct fields discovered from FUN_20c8663a0
(CB-prefix register selector dispatcher).

SM83 is the Game Boy CPU (Z80-like). mGBA emulates it for GB/GBC compatibility.
struct_key: "mGBA_SM83State" (param_1 in all SM83 CPU functions)
"""
import sys
sys.path.insert(0, r"C:\Users\nathan37\Desktop\re_toolkit")
from knowledge_bus import emit_field_access, emit_discovery

STRUCT_KEY = "mGBA_SM83State"
FUNC_VA    = "0x20c8663a0"   # CB-prefix register dispatcher

fields = [
    # offset  field_name      evidence
    (0x00,  "flags_F",        "case N: *param_1 = (zero<<7)|(carry<<4)|(*param_1&0xf) — F register"),
    (0x04,  "reg_A",          "case 7: param_1[4] = RLC result — A (accumulator)"),
    (0x05,  "reg_C",          "case 1: param_1[5] = RLC result — C register"),
    (0x06,  "reg_B",          "case 0: param_1[6] = RLC result — B register"),
    (0x07,  "reg_E",          "case 3: param_1[7] = RLC result — E register"),
    (0x08,  "reg_D",          "case 2: param_1[8] = RLC result — D register"),
    (0x09,  "reg_L",          "case 5: param_1[9] = RLC result — L register"),
    (0x0a,  "reg_H",          "case 4: param_1[10] = RLC result — H register"),
    (0x10,  "mem_addr",       "case 6 (HL): *(param_1+0x10) = HL value — memory access address"),
    (0x20,  "mem_op_type",    "case 6 (HL): param_1[0x20] = 7 — memory operation type code"),
    (0x25,  "reg_selector",   "switch(param_1[0x25]) — register index from CB opcode bits [0:2]"),
    (0x28,  "mem_callback",   "case 6 (HL): *(param_1+0x28) = FUN_20c8652c0 — async memory completion CB"),
]

print(f"Emitting {len(fields)} SM83 CPU state struct fields...")
for offset, name, evidence in fields:
    emit_field_access(
        struct_key = STRUCT_KEY,
        offset     = offset,
        field_name = name,
        layer      = "ghidra",
        func_va    = FUNC_VA,
        evidence   = evidence,
    )
    print(f"  +{offset:#05x}  {name}")

# Architectural observation: cycle-accurate memory access
emit_discovery("ghidra", "architecture_pattern", {
    "binary":   "mgba_libretro.dll",
    "pattern":  "SM83 cycle-accurate memory access via callbacks",
    "detail":   ("SM83 CPU does not read memory directly. "
                 "Sets mem_addr (+0x10) = address, mem_op_type (+0x20) = op code, "
                 "mem_callback (+0x28) = completion function. "
                 "Memory read completes asynchronously via callback on next cycle. "
                 "This decouples CPU and memory bus — explains why SM83 component "
                 "is disconnected from main execution graph."),
    "va":       FUNC_VA,
})
print("\n[KB] Architecture pattern: SM83 cycle-accurate memory callback model")
print("\nDone. KB now has SM83 + GBA struct + mCore vtable.")
