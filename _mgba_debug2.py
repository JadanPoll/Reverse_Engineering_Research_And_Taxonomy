import sys, ctypes
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
print("retro_init OK")

# Debug: count region types
k32 = ctypes.WinDLL("kernel32")
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress",ctypes.c_void_p),("AllocationBase",ctypes.c_void_p),
                ("AllocationProtect",ctypes.c_ulong),("RegionSize",ctypes.c_size_t),
                ("State",ctypes.c_ulong),("Protect",ctypes.c_ulong),("Type",ctypes.c_ulong)]

MEM_COMMIT=0x1000; MEM_PRIVATE=0x20000; MEM_MAPPED=0x40000; MEM_IMAGE=0x1000000
PAGE_GUARD=0x100; READABLE={0x02,0x04,0x20,0x40}

regions = {"private_readable":0,"private_guard":0,"mapped":0,"image":0,"free":0,"other":0}
fptr_regions = 0
addr = 0
load_base = dll._handle

r = VTableResolver(dll_path, r"TESTS\real_world\emulators\mgba\calltree.json")

for _ in range(10000):
    mbi = MBI()
    if k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
        break
    next_addr = (mbi.BaseAddress or 0) + mbi.RegionSize
    if next_addr <= addr: break

    if mbi.State != MEM_COMMIT:
        regions["free"] += 1
    elif mbi.Type == MEM_PRIVATE:
        if mbi.Protect & PAGE_GUARD:
            regions["private_guard"] += 1
        elif mbi.Protect & 0xFF in READABLE:
            regions["private_readable"] += 1
            # Quick check: any fn ptrs in this region?
            base = mbi.BaseAddress or 0
            try:
                sample = (ctypes.c_uint64 * 4).from_address(base)
                for v in sample:
                    if r._in_dll_exec(v):
                        fptr_regions += 1
                        break
            except: pass
        else:
            regions["other"] += 1
    elif mbi.Type == MEM_MAPPED: regions["mapped"] += 1
    elif mbi.Type == MEM_IMAGE:  regions["image"] += 1
    else: regions["other"] += 1

    addr = next_addr

print(f"Region summary: {regions}")
print(f"Regions with at least 1 in-DLL fn ptr: {fptr_regions}")
print(f"exec_ranges: {r._exec_ranges}")
