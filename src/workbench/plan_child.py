"""Bounded read-only planning subprocess; no detector execution or DB writes."""
import ctypes
import json
import os
import resource
import signal
import sys
from src.ohscanner.planning import preview_plan


def main():
    libc = ctypes.CDLL(None)
    if libc.prctl(1, signal.SIGKILL) != 0 or os.getppid() != int(sys.argv[1]):
        raise RuntimeError('planning parent unavailable')
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 35))
    spec = json.loads(sys.stdin.buffer.read(1024 * 1024))
    plan = preview_plan(spec['repo_dir'], spec['repository'], spec['commit'],
                        spec['includes'], spec['selected_detector_ids'],
                        spec.get('execution_budget'))
    print(json.dumps(plan, ensure_ascii=False, allow_nan=False))


if __name__ == '__main__':
    main()
