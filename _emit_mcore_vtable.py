"""
Emit mCore vtable slot mappings and additional GBAState fields
discovered from retro_run and FUN_20c8263d0 (DMA control handler).

mCore = DAT_20ca668b0 (the core interface struct, C-style vtable)
GBAState = param_1 in most mGBA core functions
"""
import sys
sys.path.insert(0, r"C:\Users\nathan37\Desktop\re_toolkit")
from knowledge_bus import emit_field_access, emit_discovery

# mCore vtable slots
MCORE_STRUCT = "mCore_vtable"
MCORE_VA     = "DAT_20ca668b0"

vtable_slots = [
    (0x3F8, "getPlatform",       "retro_run: return 0=GBA 1=GB, controls all platform branching"),
    (0x418, "setOption",         "retro_run: called with 'allowOpposingDirections' option name"),
    (0x430, "getAudioBuffer",    "retro_run: returns audio samples, followed by 512-sample batch send"),
    (0x468, "getAudioSampleRate","retro_run: compared to detect sample rate changes"),
    (0x470, "getCheatDevice",    "retro_run: returns cheat device handle, fed to cheat loop"),
    (0x4F8, "runFrame",          "retro_run: THE main execution call — one call per frame"),
    (0x538, "setKeys",           "retro_run: receives assembled key bitmask (uVar15) → GBA KEYINPUT"),
]

print(f"Emitting {len(vtable_slots)} mCore vtable slot observations...")
for offset, name, evidence in vtable_slots:
    emit_field_access(
        struct_key = MCORE_STRUCT,
        offset     = offset,
        field_name = name,
        layer      = "ghidra",
        func_va    = "0x20c85f3f0",   # retro_run
        evidence   = evidence,
    )
    print(f"  +{offset:#06x}  {name}")

# Additional GBAState fields from DMA handler + retro_run
GBA_STRUCT = "mGBA_GBAState"

extra_fields = [
    (0x0C4, "soundcnt_x_mirror",  "retro_run line: *(param_1+0xc4) = SOUNDCNT_X mirror (0x40+0x42*2)"),
    (0xBDC, "dma_ch0_cnt_h",      "FUN_20c8263d0: *(param_1+0xBDC+ch*0x24) = DMAx_CNT_H; stride=0x24"),
    (0x1839,"gb_audio_state_flag", "FUN_20c82d210 (GB MMIO): *(param_1+0x1839) != 0 guards some writes"),
    (0x1530,"gb_audio_substruct",  "FUN_20c82d210: GB-specific audio sub-struct at +0x1530"),
    (0x19D8,"gb_timing_struct",    "FUN_20c82d210: FUN_*(param_1+0x19d8) = GB timing/scheduler"),
]

print(f"\nEmitting {len(extra_fields)} additional GBAState field observations...")
for offset, name, evidence in extra_fields:
    emit_field_access(
        struct_key = GBA_STRUCT,
        offset     = offset,
        field_name = name,
        layer      = "ghidra",
        func_va    = "0x20c85f3f0",
        evidence   = evidence,
    )
    print(f"  +{offset:#06x}  {name}")

# Known gap — emit as discovery
emit_discovery("ghidra", "known_gap", {
    "binary":    "mgba_libretro.dll",
    "gap":       "DRQ (DMA Request from Game Pak) not implemented",
    "evidence":  "FUN_20c8263d0 case (param3 & 0x800): FUN_20c7f9f60(..., 'DRQ not implemented')",
    "va":        "0x20c8263d0",
})
print("\n[KB] Emitted known gap: DRQ not implemented")
print("\nDone.")
