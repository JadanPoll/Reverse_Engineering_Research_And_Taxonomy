"""
Find the ARM7 runFrame function by reading mCore vtable slot +0x4F8
after retro_load_game (GBA ROM loaded → getPlatform()==0 path).
"""
import sys, ctypes, struct
sys.path.insert(0, r"C:\Users\nathan37\Desktop\re_toolkit")
from pe_utils import PE
from dynamic.vtable_resolver import VTableResolver

dll_path = r"TESTS\real_world\emulators\mgba\mgba_libretro.dll"
dll  = ctypes.CDLL(dll_path)
pe   = PE(dll_path)
lb   = dll._handle
rebase = lb - pe.image_base

# Setup callbacks
ENV_CB=ctypes.CFUNCTYPE(ctypes.c_bool,ctypes.c_uint,ctypes.c_void_p)
VID_CB=ctypes.CFUNCTYPE(None,ctypes.c_void_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_size_t)
AUD_CB=ctypes.CFUNCTYPE(None,ctypes.c_int16,ctypes.c_int16)
AUDB_CB=ctypes.CFUNCTYPE(ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t)
INP_CB=ctypes.CFUNCTYPE(None)
INPS_CB=ctypes.CFUNCTYPE(ctypes.c_int16,ctypes.c_uint,ctypes.c_uint,ctypes.c_uint,ctypes.c_uint)
_env=ENV_CB(lambda cmd,data:False); _vid=VID_CB(lambda d,w,h,p:None)
_aud=AUD_CB(lambda l,r:None); _audb=AUDB_CB(lambda b,f:f)
_inp=INP_CB(lambda:None); _inps=INPS_CB(lambda p,d,i,b:0)
dll.retro_set_environment(_env); dll.retro_set_video_refresh(_vid)
dll.retro_set_audio_sample(_aud); dll.retro_set_audio_sample_batch(_audb)
dll.retro_set_input_poll(_inp); dll.retro_set_input_state(_inps)
dll.retro_init()

# Minimal GBA ROM
rom = bytearray(0x200)
rom[0:4] = b'\xFE\xFF\xFF\xEA'
rom[178] = 0x96
chk = sum((-b)&0xFF for b in rom[0xA0:0xBD])
rom[0xBD] = (chk-0x19)&0xFF
rom_buf = (ctypes.c_uint8*len(rom))(*rom)

class RetroGameInfo(ctypes.Structure):
    _fields_=[("path",ctypes.c_char_p),("data",ctypes.c_void_p),
              ("size",ctypes.c_size_t),("meta",ctypes.c_char_p)]
gi=RetroGameInfo(); gi.path=b"test.gba"
gi.data=ctypes.cast(rom_buf,ctypes.c_void_p); gi.size=len(rom); gi.meta=None
dll.retro_load_game.restype=ctypes.c_bool
ok=dll.retro_load_game(ctypes.byref(gi))
print(f"retro_load_game: {'OK' if ok else 'FAILED'}")

# Find mCore pointer (DAT_20ca668b0)
# We know from retro_run analysis: DAT_20ca668b0 is the mCore*
# Its Ghidra VA is 0x20ca668b0 → runtime = 0x20ca668b0 + rebase
mcore_ptr_gva = 0x20ca668b0
mcore_ptr_runtime = mcore_ptr_gva + rebase
try:
    mcore = ctypes.c_uint64.from_address(mcore_ptr_runtime).value
    print(f"mCore* = {mcore:#x}")
    if mcore:
        # Read vtable (first field)
        vtbl = ctypes.c_uint64.from_address(mcore).value
        print(f"mCore vtable = {vtbl:#x}  (ghidra_va = {vtbl-rebase:#x})")

        # Read runFrame slot at +0x4F8
        run_frame_slot = ctypes.c_uint64.from_address(vtbl + 0x4F8).value
        run_frame_gva  = run_frame_slot - rebase
        print(f"\nmCore::runFrame = {run_frame_slot:#x}  (ghidra_va = {run_frame_gva:#x})")

        # Read getPlatform slot at +0x3F8
        get_plat_slot = ctypes.c_uint64.from_address(vtbl + 0x3F8).value
        get_plat_gva  = get_plat_slot - rebase
        print(f"mCore::getPlatform = {get_plat_slot:#x}  (ghidra_va = {get_plat_gva:#x})")

        # Call getPlatform to confirm GBA=0
        gp_fn = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)(get_plat_slot)
        platform = gp_fn(mcore)
        print(f"getPlatform() = {platform}  (0=GBA, 1=GB)")
except OSError as e:
    print(f"Error reading mCore: {e}")
