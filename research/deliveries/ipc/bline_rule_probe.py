"""Instrument the four new rules' decision points over the 54 pinned components.

The detector's candidate counts say a rule never fired. They do not say whether
the code it keys on was ever reached. This probe wraps the analysis methods and
counts, per component:

  index_sites / index_bound_known   request-derived subscript sites, and how many
                                    selected a buffer whose capacity is declared
  dest_sites / dest_bound_known     ReadRawData(dst, n) sites with a parcel length,
                                    and how many had a declared destination capacity
  invalidations / views_invalidated parcel reuse/rewind events, and views they hit
  reply_writes / disclosure_writes  reply writes, and writes of a disclosure result
  actions / reset_actions / ...     modelled sensitive actions, and the identity-flow
                                    preconditions on those paths

It does not change any finding: every wrapper delegates to the original method.
"""
import argparse, collections, hashlib, json, os, subprocess, sys, time

WT = '/home/audit/ohscanner/worktrees/parallel-ipc-20261017'
sys.path.insert(0, WT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.parser.ast import parse_source
from src.ohscanner.contracts import SourceUnit, ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.detectors.interface import analysis as A
import bline_direct_measure as M

ROOTS = ['/home/audit/openharmony-audit/perf-corpus', '/home/audit/corpus-ipc-widen',
         '/home/audit/corpus-ipc-shape', '/home/audit/corpus-ipc-bline',
         '/home/audit/corpus-ipc-extra', '/home/audit/corpus-ipc-batch3']

COUNTS = collections.Counter()


def wrap(name, before):
    original = getattr(A.Interpreter, name)

    def patched(self, *args, **kwargs):
        before(COUNTS, self, *args, **kwargs)
        return original(self, *args, **kwargs)

    setattr(A.Interpreter, name, patched)


def before_index(c, self, fn, node, state, base, index):
    c['index_sites'] += 1
    if index.kind == 'request':
        c['index_request'] += 1
        if self.capacities.get(A.terminal(base)) is not None:
            c['index_capacity_known'] += 1


def before_dest(c, self, fn, node, state, name, args):
    c['dest_sites'] += 1
    if len(args) >= 2 and args[1].kind == 'request':
        c['dest_request'] += 1
        if self.capacities.get(A.terminal(args[0].key)) is not None:
            c['dest_capacity_known'] += 1


def before_invalidate(c, self, state, receiver, call):
    c['invalidations'] += 1
    c['views_invalidated'] += len([v for v in state.parcel_views
                                   if state.env.get(v) is not None
                                   and state.env[v].kind == 'parcel_view'
                                   and state.env[v].subject == receiver])


def before_reply(c, self, fn, node, state, name, args):
    c['reply_writes'] += 1
    c['disclosure_writes'] += sum(1 for v in args if v.kind == 'sensitive_result')


def before_action(c, self, fn, node, state, name, args, *rest, **kw):
    sensitive = (name in self.policy.sensitive_calls
                 or name in self.policy.object_sensitive_calls)
    if not sensitive:
        return
    c['actions'] += 1
    if state.reset:
        c['reset_actions'] += 1
        if state.auth:
            c['reset_actions_with_auth'] += 1
            if state.identity_discarded:
                c['reset_actions_discarded'] += 1
        c['reset_actions_discarded_any'] += bool(state.identity_discarded)


def git(repo, *args):
    return subprocess.run(['git', '-C', repo, *args], capture_output=True,
                          text=True, check=True).stdout.strip()


def targets():
    seen = {}
    for root in ROOTS:
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            d = os.path.join(root, name)
            if os.path.isdir(os.path.join(d, '.git')) and name not in seen:
                seen[name] = d
    return sorted(seen.items())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--only', default=None)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    wrap('parcel_index_bound', before_index)
    wrap('parcel_destination_bound', before_dest)
    wrap('invalidate_views', before_invalidate)
    wrap('reply_flow', before_reply)
    wrap('action', before_action)
    items = targets()
    if a.only:
        items = [i for i in items if i[0] in a.only.split(',')]
    rows = []
    for i, (name, repo) in enumerate(items, 1):
        COUNTS.clear()
        commit = git(repo, 'rev-parse', 'HEAD')
        units = []
        for path, mode, kind, oid in M.tree(repo, commit):
            ok, why = M.eligible(path, mode, kind)
            if not ok:
                continue
            data = M.git(repo, 'cat-file', 'blob', oid)
            if len(data) > M.MAX_BYTES:
                continue
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                continue
            index = parse_source(text, language=M.EXTS[os.path.splitext(path)[1].lower()])
            units.append(SourceUnit(path, M.EXTS[os.path.splitext(path)[1].lower()],
                                    text, hashlib.sha256(data).hexdigest(),
                                    index.parse_status))
        units = [u for u in units if u.parse_status == 'complete']
        request = ScanRequest('ipc-probe', 'openharmony/x', commit,
                              snapshot_digest(tuple(units)), 'current-component:openharmony/x')
        ctx = ScanContext(request, tuple(units), {'ast': {u.path: {} for u in units}})
        t = time.time()
        result = IpcInterfaceDetector().detect(ctx, ctx.units)
        row = {'component': name, 'commit': commit,
               'seconds': round(time.time() - t, 1), **dict(COUNTS)}
        rows.append(row)
        print('[%d/%d] %s %s' % (i, len(items), name, json.dumps(row)), flush=True)
        json.dump(rows, open(os.path.join(a.out, 'probe.json'), 'w'), indent=2)
    total = collections.Counter()
    for row in rows:
        for k, v in row.items():
            if k not in ('component', 'commit', 'seconds'):
                total[k] += v
    print(json.dumps({'components': len(rows), 'totals': dict(total)}, indent=2))
    json.dump({'components': len(rows), 'totals': dict(total), 'rows': rows},
              open(os.path.join(a.out, 'probe.json'), 'w'), indent=2)


if __name__ == '__main__':
    main()
