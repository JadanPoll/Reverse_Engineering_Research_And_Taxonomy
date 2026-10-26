"""Dump heap-discovered function VA seeds to JSON for graph-metrics --extra-seeds."""
import sys, ctypes, json
sys.path.insert(0, ".")
from dynamic.vtable_resolver import VTableResolver

dll_path = r"TESTS\real_world\emulators\mgba\mgba_libretro.dll"
dll = ctypes.CDLL(dll_path)

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

import struct as _struct
rom = bytearray(0x200)
rom[0:4] = b'\xFE\xFF\xFF\xEA'
rom[178] = 0x96
chk = sum((-b) & 0xFF for b in rom[0xA0:0xBD])
chk = (chk - 0x19) & 0xFF
rom[0xBD] = chk
rom_bytes = bytes(rom)

class RetroGameInfo(ctypes.Structure):
    _fields_ = [("path",ctypes.c_char_p),("data",ctypes.c_void_p),
                ("size",ctypes.c_size_t),("meta",ctypes.c_char_p)]
rom_buf = (ctypes.c_uint8*len(rom_bytes))(*rom_bytes)
gi = RetroGameInfo()
gi.path = b"test.gba"; gi.data = ctypes.cast(rom_buf, ctypes.c_void_p)
gi.size = len(rom_bytes); gi.meta = None
dll.retro_load_game.restype = ctypes.c_bool
ok = dll.retro_load_game(ctypes.byref(gi))
print(f"retro_load_game: {'OK' if ok else 'FAILED'}")

r = VTableResolver(dll_path, r"TESTS\real_world\emulators\mgba\calltree.json")
clusters = r.scan_heap_for_fptrs(min_cluster=2, max_regions=1000)

vas = list({hex(e["ghidra_va"]) for v in clusters.values() for e in v})
out = r"TESTS\real_world\emulators\mgba\runtime_seeds.json"
with open(out, "w") as f:
    json.dump(vas, f, indent=2)
print(f"Wrote {len(vas)} VAs to {out}")
