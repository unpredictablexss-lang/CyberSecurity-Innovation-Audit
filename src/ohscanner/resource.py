"""Shared bounded resource measurements for reproducible scan deliverables."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import time
from typing import Any


def _windows_rss() -> tuple[int | None, int | None]:
    try:
        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_uint32),
                ("PageFaultCount", ctypes.c_uint32),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]
        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetCurrentProcess()
        if not ctypes.windll.psapi.GetProcessMemoryInfo(
            handle, ctypes.byref(counters), counters.cb
        ):
            return None, None
        return int(counters.WorkingSetSize), int(counters.PeakWorkingSetSize)
    except Exception:
        return None, None


def _proc_rss() -> tuple[int | None, int | None]:
    try:
        values: dict[str, int] = {}
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                key, raw = line.split(":", 1)
                values[key] = int(raw.strip().split()[0]) * 1024
        return values.get("VmRSS"), values.get("VmHWM")
    except Exception:
        return None, None


def _posix_rss() -> tuple[int | None, int | None]:
    current, peak = _proc_rss()
    if current is not None or peak is not None:
        return current, peak
    try:
        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF)
        scale = 1024 if os.name != "nt" else 1
        return int(usage.ru_maxrss) * scale, int(usage.ru_maxrss) * scale
    except Exception:
        return None, None


def rss_bytes() -> dict[str, Any]:
    if os.name == "nt":
        current, peak = _windows_rss()
        source = "windows_process_memory_counters"
    else:
        current, peak = _posix_rss()
        source = "proc_self_status_or_getrusage"
    return {
        "current_bytes": current,
        "peak_bytes": peak,
        "source": source,
        "measured": current is not None or peak is not None,
    }


def start_resource_monitor() -> dict[str, Any]:
    return {
        "started_unix_seconds": time.time(),
        "started_monotonic_seconds": time.perf_counter(),
        "start_rss": rss_bytes(),
    }


def finish_resource_monitor(started: dict[str, Any]) -> dict[str, Any]:
    end_rss = rss_bytes()
    return {
        "wall_seconds": max(0.0, time.perf_counter() - started["started_monotonic_seconds"]),
        "started_unix_seconds": started["started_unix_seconds"],
        "start_rss": started["start_rss"],
        "end_rss": end_rss,
        "peak_rss_bytes": end_rss.get("peak_bytes"),
        "rss_measured": bool(end_rss.get("measured")),
    }