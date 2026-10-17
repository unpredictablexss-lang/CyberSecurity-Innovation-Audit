"""Measure the per-family fixture directories, and print what the depth unit pins.

Read-only. It loads `tests/test_ipc_family_depth.py` by path and uses that unit's own
helpers, so the candidate sets printed here are the candidate sets the tests compute
-- the point being that the pinned table in that unit is a recorded measurement and
not a transcription of an idea.

    python research/deliveries/ipc/family_dir_measurement.py            # every family
    python research/deliveries/ipc/family_dir_measurement.py cap01 auth02

Each fixture line is `<family> <file> <status> <candidates>`; limitations that name a
caller-role predicate, a one-hop hop or an account-model fact are printed under it.
The `diff=` lines at the end are the minimal-pair budgets (`changed_lines`) with the
candidate set on each side, so a pair whose budget or whose expectation moved is
visible without running the tests.
"""
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector  # noqa: E402

DEPTH = ROOT / 'tests/test_ipc_family_depth.py'
_spec = importlib.util.spec_from_file_location('depth_unit', DEPTH)
unit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(unit)

INTERESTING = ('caller-role', 'one-hop', 'Cross-TU', 'not unique', 'account-model',
               'Dispatch handler')


def run_of(family_dir, filename):
    return unit.run_of(family_dir, filename)


def report(family_dir):
    manifest = unit.BASE / family_dir / 'manifest.json'
    listed = ({item['file'] for item in json.loads(manifest.read_text())}
              if manifest.exists() else set())
    for path in sorted((unit.BASE / family_dir).glob('*.cpp')):
        run = run_of(family_dir, path.name)
        print('%-8s %-44s %-10s %s%s' % (
            family_dir, path.name, run.status, unit.candidates(run),
            '' if path.name in listed else '   <-- no manifest row'))
        for limit in run.limitations:
            if any(token in limit for token in INTERESTING):
                print('            L:', limit)


def pairs():
    for family_dir, positive, control, budget in unit.REVIEWED_PAIRS:
        measured = unit.changed_lines(family_dir, positive, control)
        print('%-8s %-42s vs %-42s diff=%d (pinned %d)  %s -> %s' % (
            family_dir, positive, control, measured, budget,
            unit.candidates(run_of(family_dir, positive)),
            unit.candidates(run_of(family_dir, control))))
    for family_dir, left, right, budget in unit.INVARIANCE_PAIRS:
        measured = unit.changed_lines(family_dir, left, right)
        print('%-8s %-42s == %-42s diff=%d (pinned %d)  both %s' % (
            family_dir, left, right, measured, budget,
            unit.candidates(run_of(family_dir, left))))


def main(argv):
    for family_dir in (argv or ('auth02', 'auth04', 'cap01')):
        report(family_dir)
    print()
    pairs()
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
