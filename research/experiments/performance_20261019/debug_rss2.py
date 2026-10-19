import ctypes
from ctypes import wintypes
class PMC(ctypes.Structure):
    _fields_=[("cb",wintypes.DWORD),("PageFaultCount",wintypes.DWORD),("PeakWorkingSetSize",ctypes.c_size_t),("WorkingSetSize",ctypes.c_size_t),("QuotaPeakPagedPoolUsage",ctypes.c_size_t),("QuotaPagedPoolUsage",ctypes.c_size_t),("QuotaPeakNonPagedPoolUsage",ctypes.c_size_t),("QuotaNonPagedPoolUsage",ctypes.c_size_t),("PagefileUsage",ctypes.c_size_t),("PeakPagefileUsage",ctypes.c_size_t)]
k=ctypes.WinDLL("kernel32",use_last_error=True); p=ctypes.WinDLL("psapi",use_last_error=True)
p.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(PMC),wintypes.DWORD]; p.GetProcessMemoryInfo.restype=wintypes.BOOL
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
h=k.OpenProcess(0x0400|0x0010,False,ctypes.windll.kernel32.GetCurrentProcessId())
c=PMC(); c.cb=ctypes.sizeof(c)
ok=p.GetProcessMemoryInfo(h,ctypes.byref(c),c.cb)
print("handle",h,"ok",ok,"err",ctypes.get_last_error(),"rss",c.PeakWorkingSetSize,"ws",c.WorkingSetSize)
