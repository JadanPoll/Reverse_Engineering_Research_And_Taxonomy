"""
Test: does retro_load_game populate the function pointer dispatch tables?
Uses a minimal GBA ROM stub (just enough for mGBA to accept).
"""
import sys, ctypes, struct
sys.path.insert(0, ".")
from dynamic.vtable_resolver import VTableResolver

dll_path = r"TESTS\real_world\emulators\mgba\mgba_libretro.dll"
dll = ctypes.CDLL(dll_path)

# ── callbacks ─────────────────────────────────────────────────────────────────
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
print("retro_init OK")

# ── minimal GBA ROM stub ──────────────────────────────────────────────────────
# ARM branch to self (infinite loop at 0x08000000)
rom = bytearray(0x200)
rom[0:4] = b'\xFE\xFF\xFF\xEA'          # B  0x08000000  (branch to self)
# Nintendo logo (bytes 4..159) - mGBA doesn't strictly validate
rom[4:160] = bytes(156)
rom[160:172] = b'TESTROM\x00\x00\x00\x00\x00'  # game title
rom[172:176] = b'TEST'                    # game code
rom[176:178] = b'00'                      # maker code
rom[178] = 0x96                           # fixed value
rom[179] = 0x00                           # unit code
rom[180] = 0x00                           # device type
rom[188] = 0x00                           # ROM version
# Compute header checksum (bytes 0xA0..0xBC)
chk = 0
for b in rom[0xA0:0xBD]:
    chk = (chk - b) & 0xFF
chk = (chk - 0x19) & 0xFF
rom[0xBD] = chk
rom_bytes = bytes(rom)

class RetroGameInfo(ctypes.Structure):
    _fields_ = [("path", ctypes.c_char_p), ("data", ctypes.c_void_p),
                ("size", ctypes.c_size_t), ("meta", ctypes.c_char_p)]

rom_buf = (ctypes.c_uint8 * len(rom_bytes))(*rom_bytes)
gi = RetroGameInfo()
gi.path = b"test.gba"
gi.data = ctypes.cast(rom_buf, ctypes.c_void_p)
gi.size = len(rom_bytes)
gi.meta = None
dll.retro_load_game.restype = ctypes.c_bool
ok = dll.retro_load_game(ctypes.byref(gi))
print(f"retro_load_game: {'OK' if ok else 'FAILED'}")

if not ok:
    sys.exit(1)

# ── now scan heap for fn ptrs ─────────────────────────────────────────────────
r = VTableResolver(dll_path, r"TESTS\real_world\emulators\mgba\calltree.json")
print(f"exec_ranges: {len(r._exec_ranges)}  range={r._exec_ranges[0] if r._exec_ranges else 'none'}")

clusters = r.scan_heap_for_fptrs(min_cluster=2, max_regions=1000)
r.print_heap_fptrs(clusters, top_clusters=10)
named = sum(1 for v in clusters.values() for e in v if not e["name"].startswith("FUN_"))
total = sum(len(v) for v in clusters.values())
print(f"\nTotal: {len(clusters)} clusters, {total} fn ptrs  ({named} named)")
