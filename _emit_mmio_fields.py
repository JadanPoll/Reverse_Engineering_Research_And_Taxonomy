"""
Emit MMIO struct field mappings discovered in FUN_20c82c8f0 (GBA MMIO write handler)
to the knowledge bus as confirmed field_access observations.

Fields confirmed from one function's pseudocode alone — no runtime needed.
struct_key: "mGBA_GBAState" (the unnamed longlong *param_1 in all mGBA core functions)
"""
import sys
sys.path.insert(0, r"C:\Users\nathan37\Desktop\re_toolkit")
from knowledge_bus import emit_field_access

STRUCT_KEY = "mGBA_GBAState"
LAYER      = "ghidra"
FUNC_VA    = "0x20c82c8f0"   # FUN_20c82c8f0 = MMIO write dispatcher

fields = [
    # offset  field_name              evidence
    (0x040,  "io_mirror_array",       "all I/O writes: *(param_1+0x40 + reg_idx*2) = value"),
    (0x172,  "keycnt",                "case 0x132: *(param_1+0x172) = uVar4 & 0xC3FF"),
    (0x1b26, "key_input_state",       "case 0x132: bounds check + update with live key bits"),
    (0x240,  "ie",                    "case 0x200 (IE): *(param_1+0x240) = uVar4"),
    (0x242,  "if_flags",              "case 0x202 (IF): *(param_1+0x242) &= ~uVar4 (write-to-clear)"),
    (0x248,  "ime",                   "case 0x208 (IME): *(param_1+0x248) = uVar4 & 1"),
    (0x24a,  "ie_unused_20a",         "case 0x20A: direct write, returns immediately"),
    (0xbcc,  "cpu_bios_mode",         "case 0x300 (HALTCNT): checked before halting CPU"),
    (0x340,  "cpu_halt_state",        "case 0x300: *(param_1+0x340) != 0 check before halt/stop"),
    (0x1528, "audio_struct",          "all sound cases 0x60-0x84: FUN_*(param_1+0x1528, ...)"),
    (0x18c8, "sio_struct",            "serial cases 0x120-0x132: FUN_*(param_1+0x18c8, ...)"),
    (0x1c1b, "mgba_debug_enable",     "case 0xFFF780: set when value == 0xC0DE"),
    (0x1c1c, "mgba_debug_str_buf",    "range 0xFFF600-0x6FF: *(param_1+0x1c1c+offset) = uVar4"),
    # DMA-adjacent (from array access pattern in 0x9E/0xB0 cases)
    (0x040,  "dma_regs_in_io_mirror", "DMA cases: param_1+0x40 + (addr>>1)*2 pattern"),
]

print(f"Emitting {len(fields)} field_access observations for {STRUCT_KEY}...")
for offset, name, evidence in fields:
    emit_field_access(
        struct_key = STRUCT_KEY,
        offset     = offset,
        field_name = name,
        layer      = LAYER,
        func_va    = FUNC_VA,
        evidence   = evidence,
    )
    print(f"  +{offset:#06x}  {name}")

print(f"\nDone. Run `py -3.13 cli.py kb` to verify.")
