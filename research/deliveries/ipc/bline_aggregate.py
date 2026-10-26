"""Aggregate the per-component direct reports into one table."""
import argparse, collections, json, os

NEW = ['ipc.parcel.bounds', 'ipc.parcel.write-bounds', 'ipc.parcel.lifecycle',
       'ipc.auth.flow', 'ipc.data.sensitive-flow']
OLD = ['ipc.relay.descriptor-boundary', 'ipc.auth.missing',
       'ipc.auth.caller-class', 'ipc.auth.object-owner', 'ipc.auth.identity-domain',
       'ipc.auth.service-identity', 'ipc.auth.request-identity',
       'ipc.auth.guard-coverage', 'ipc.capability.export',
       'ipc.parcel.copy-range', 'ipc.parcel.position-underflow']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', required=True)
    a = ap.parse_args()
    comps = []
    per_rule = collections.Counter()
    per_rule_components = collections.defaultdict(set)
    per_rule_pass = collections.defaultdict(collections.Counter)
    for name in sorted(os.listdir(a.dir)):
        p = os.path.join(a.dir, name, 'report.json')
        if not os.path.exists(p):
            continue
        r = json.load(open(p))
        all_, comp = r['passes']['all-files'], r['passes']['complete-ast']
        row = {'component': name, 'repository': r['repository'], 'commit': r['commit'],
               'dirty': r.get('dirty'), 'selected_files': r['scope'].get('selected_files', 0),
               'parse': r['parse'],
               'all_candidates': all_['candidates'], 'complete_candidates': comp['candidates'],
               'complete_rules': comp['rules'], 'status': comp['status'],
               'dispatch_coverage': (comp['limitations'][0] if comp['limitations'] else None)}
        comps.append(row)
        for rule, n in comp['rules'].items():
            per_rule[rule] += n
            per_rule_components[rule].add(name)
            per_rule_pass[rule]['complete-ast'] += n
        for rule, n in all_['rules'].items():
            per_rule_pass[rule]['all-files'] += n
    summary = {
        'components': len(comps),
        'files': sum(c['selected_files'] or 0 for c in comps),
        'complete_ast': sum(c['parse']['complete'] for c in comps),
        'partial_ast': sum(c['parse']['partial'] for c in comps),
        'candidates_complete_ast': sum(c['complete_candidates'] for c in comps),
        'rules': {rule: {'complete-ast': per_rule.get(rule, 0),
                         'all-files': per_rule_pass[rule].get('all-files', 0),
                         'components': len(per_rule_components.get(rule, ()))}
                  for rule in OLD + NEW},
        'zero_candidate_components': [c['component'] for c in comps
                                      if c['complete_candidates'] == 0],
        'no_applicable_units': [c['component'] for c in comps
                                if not c['selected_files']],
        'validated_vulnerability': 0,
    }
    json.dump({'summary': summary, 'components': comps},
              open(os.path.join(a.dir, 'aggregate.json'), 'w'), indent=2, ensure_ascii=False)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
