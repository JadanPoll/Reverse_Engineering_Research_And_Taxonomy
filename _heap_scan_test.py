import sys, ctypes, traceback
sys.path.insert(0, ".")
from dynamic.vtable_resolver import VTableResolver

dll = ctypes.CDLL(r"TESTS\real_world\emulators\mgba\mgba_libretro.dll")
ENV_CB  = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_uint, ctypes.c_void_p)
VID_CB  = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_size_t)
AUD_CB  = ctypes.CFUNCTYPE(None, ctypes.c_int16, ctypes.c_int16)
AUDB_CB = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t)
INP_CB  = ctypes.CFUNCTYPE(None)
INPS_CB = ctypes.CFUNCTYPE(ctypes.c_int16, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint)
_env  = ENV_CB(lambda cmd, data: False)
_vid  = VID_CB(lambda d, w, h, p: None)
_aud  = AUD_CB(lambda l, r: None)
_audb = AUDB_CB(lambda b, f: f)
_inp  = INP_CB(lambda: None)
_inps = INPS_CB(lambda p, d, i, b: 0)
dll.retro_set_environment(_env);      dll.retro_set_video_refresh(_vid)
dll.retro_set_audio_sample(_aud);     dll.retro_set_audio_sample_batch(_audb)
dll.retro_set_input_poll(_inp);       dll.retro_set_input_state(_inps)
dll.retro_init()
print("retro_init OK")

try:
    r = VTableResolver(
        r"TESTS\real_world\emulators\mgba\mgba_libretro.dll",
        r"TESTS\real_world\emulators\mgba\calltree.json"
    )
    print(f"VTableResolver OK, exec_ranges={len(r._exec_ranges)}")
    clusters = r.scan_heap_for_fptrs(min_cluster=3, max_regions=500)
    r.print_heap_fptrs(clusters, top_clusters=8)
except Exception:
    traceback.print_exc()
