import ctypes
class PMC(ctypes.Structure):
    _fields_=[("cb",ctypes.c_uint32),("PageFaultCount",ctypes.c_uint32),("PeakWorkingSetSize",ctypes.c_size_t),("WorkingSetSize",ctypes.c_size_t),("QuotaPeakPagedPoolUsage",ctypes.c_size_t),("QuotaPagedPoolUsage",ctypes.c_size_t),("QuotaPeakNonPagedPoolUsage",ctypes.c_size_t),("QuotaNonPagedPoolUsage",ctypes.c_size_t),("PagefileUsage",ctypes.c_size_t),("PeakPagefileUsage",ctypes.c_size_t)]
for lib,name in [(ctypes.windll.psapi,"psapi"),(ctypes.windll.kernel32,"K32GetProcessMemoryInfo")]:
    c=PMC(); c.cb=ctypes.sizeof(c); h=ctypes.windll.kernel32.GetCurrentProcess()
    fn=getattr(lib, "GetProcessMemoryInfo" if name=="psapi" else name)
    ok=fn(h,ctypes.byref(c),c.cb)
    print(name, ok, ctypes.get_last_error(), c.PeakWorkingSetSize)
