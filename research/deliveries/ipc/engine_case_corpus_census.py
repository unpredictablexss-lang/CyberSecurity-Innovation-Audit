"""Do the five engine cases the depth unit fixtures cover occur in real code?

Read-only. Answers the gap the delivery doc `20261017-engine-case-coverage-six-families.md`
records in its §10 item 4: the fixtures in `tests/fixtures/ipc/<family>/` were written
to exercise five engine shapes, and nothing established whether those shapes occur in
the real OpenHarmony components the lane has already audited. A fixture that fires is
a design control; a shape that never occurs in the corpus is a control for a situation
the corpus does not have, and that difference is what this instrument measures.

Three independent parts, none of which runs the detector:

  A. A source-shape census over the three corpora on disk, counting each shape.
  B. A census of the saved reports of the audit runs: what the persisted artifacts
     do carry, per rule and per candidate.
  C. The overlap of the two, read through one key: candidates that sit in the files
     part A found the shape in. That is the part that turns a shape count into a
     statement about candidates.

Part B also exists because of what part A cannot settle. The engine's case-level
reasoning (the credit, the refusal, the shadow) comes out of
`IpcInterfaceDetector.detect` as `run.limitations` entries; whether those entries
reach a saved report is a separate question, and this instrument answers it by
reading the reports rather than by asserting it.

Every count is a shape count, never a finding count and never a vulnerability claim.
A shape is a necessary condition for one of the engine's cases, not a candidate.

Scope口径, stated because it bounds every number here: part A walks each corpus
component dropping the same whole-segment test/mock/sample/example/vendored
directories the run's scope plan drops, so a shape count is comparable to what the
detector could have seen and not an upper bound over test code. The list is the one
the lane's earlier census (`widen_shape_census.py`) already uses. It is a segment
rule: `rdbmock/` is not the segment `mock` and survives both. Part D checks each
shape's files against the saved plan rather than trusting the list, which is how the
`rdbmock`/`kvstoremock` question got answered when this instrument was written.

Part A also reads the corpus working trees, not the pinned blobs of each component's
audited commit; a component whose tree moved after the audit would have its shapes
attributed to the newer tree.

`--root` and `--reports` may be repeated; each root holds one component per
subdirectory.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

# The three corpora the lane cloned, and the two saved report trees, so the
# instrument reproduces the lane's own numbers with no arguments.
DEFAULT_ROOTS = (
    Path('/home/audit/corpus-ipc-bline'),
    Path('/home/audit/corpus-ipc-shape'),
    Path('/home/audit/corpus-ipc-widen'),
)
DEFAULT_REPORTS = (
    Path('/home/audit/wtmp/ipc-audit-all'),
    Path('/home/audit/wtmp/ipc-audit-bline'),
)

SOURCE_SUFFIXES = ('.cpp', '.cc', '.cxx', '.h', '.hpp', '.hh')
MODELS = Path(__file__).resolve().parents[3] / 'src/ohscanner/detectors/interface/models.py'

# The production-segment exclusion list the run's scope plan uses, taken from the
# lane's established census (`widen_shape_census.py`) so the two instruments count
# over the same tree. It is the segment rule as written: a whole path segment has to
# be one of these names, so `rdbmock/` and `kvstoremock/` survive it, and that is
# checked against the saved plan below rather than assumed.
EXCLUDED_SEGMENTS = {
    'test', 'tests', 'unittest', 'unittests', 'fuzztest', 'fuzz',
    'mock', 'mocks', 'sample', 'samples', 'example', 'examples',
    'demo', 'demos', 'benchmark', 'benchmarks',
    'third_party', 'thirdparty', '3rdparty',
}

# The case-level sentences the engine records, as they appear in
# `IpcInterfaceDetector.detect(...).limitations`. If any of these reaches a saved
# report, part B's persistence finding is wrong and the census has to say so.
CASE_TOKENS = ('one-hop', 'Cross-TU', 'not unique', 'credited', 'shadow',
               'Dispatch handler', 'caller-role')

# Shape S1: how a parcel arrives. Both halves count any binding of the type, not
# only entry parameters, because telling an entry parameter apart from a local needs
# the signature graph the detector has and this instrument does not.
PARCEL_BINDING = re.compile(r'\b(const\s+)?MessageParcel\s*&\s*(\w+)')

# Shape S2: an out-of-class definition, `ReturnType Owner::Name(`. The return type is
# required and must be separated from the owner by whitespace, which is what excludes
# a call standing at the start of a line. Keyword-led lines are excluded separately:
# `return Factory::Make(x);` and `case X::Y(` satisfy the type rule and are not
# definitions. What remains can still be a macro invocation spelled like a qualified
# call, so S2's number is a proxy for "the name has more than one defining owner" --
# a necessary condition for the engine's not-unique refusal, not a count of refusals.
QUALIFIED_DEF = re.compile(r'^\s*([\w:<>,\s*&]+?)\s+(\w+)::(\w+)\s*\(')
KEYWORD_LED = re.compile(
    r'^\s*(?:return|case|if|else|while|for|switch|do|break|continue|goto|throw|'
    r'new|delete|using|template|sizeof|static_assert|catch|try|co_return|co_await)\b')

# Shape S3, the file-scope half: a definition with no `Owner::` qualifier. A line
# ending in `;` is a declaration and is counted separately, because the engine's rule
# is about a name defined in the scanned sources.
FREE_DEF = re.compile(r'^\s*(?:static\s+)?(?:bool|int|int32_t|int64_t|void|unsigned)\s+(\w+)\s*\(')

# Shape S4: an object-like macro (no parameter list right after the name) that is also
# used as a class name. The fixture shape is `class Stub` with `#define Stub <real>`,
# so three counts are reported: the macro declared as `class`/`struct`, and -- the
# fixture's shape exactly -- such a macro whose replacement is a single identifier,
# which is what makes the macro a renaming of the class rather than an attribute
# spliced into the class head.
OBJECT_MACRO = re.compile(r'^\s*#\s*define\s+(\w+)(?!\s*\()\s+(\S+)\s*$')
CLASS_DECL = re.compile(r'^\s*(?:class|struct)\s+(\w+)\b')
QUALIFIED_USE = re.compile(r'\b(\w+)::')
SINGLE_IDENTIFIER = re.compile(r'^[A-Za-z_]\w*(?:::\w+)*$')

# Shape S5: the capability-export writers the policy names.
EXPORT_CALLS = ('WriteRemoteObject', 'WriteFileDescriptor')


def sha256_of(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reviewed_names():
    """The reviewed caller-role predicate names, read out of the policy.

    Read as text rather than imported: the instrument must not depend on the
    detector importing cleanly, and the hash of the file it read is reported, so
    the name list has provenance either way.
    """
    block = MODELS.read_text().split('caller_role_guards', 1)
    if len(block) != 2:
        raise SystemExit('caller_role_guards not found in ' + str(MODELS))
    names = []
    for line in block[1].splitlines():
        match = re.match(r'\s*\("(\w+)",\s*"(\w+)",', line)
        if match:
            names.append((match.group(1), match.group(2)))
        elif names and line.strip().startswith(')'):
            break
    if not names:
        raise SystemExit('no reviewed caller-role names parsed from ' + str(MODELS))
    return names


def source_files(component):
    for dirpath, dirnames, filenames in os.walk(component):
        dirnames[:] = [name for name in dirnames
                       if name.lower() not in EXCLUDED_SEGMENTS and name != '.git']
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            if path.suffix not in SOURCE_SUFFIXES:
                continue
            yield path


class Shapes:
    """The five shapes' counts, and the corpus files each one occurs in.

    File sets are keyed `<component>/<repo-relative path>`, which is the key part C
    joins the saved reports on: a report's candidate names its file repo-relative,
    and the corpus directory is named for the repository.
    """

    def __init__(self, role_names):
        self.role_names = tuple(name for name, _ in role_names)
        self.parcel_const = 0
        self.parcel_ref = 0
        self.parcel_files = set()
        self.parcel_const_files = set()
        self.qualified_defs = {}       # name -> set of owners
        self.qualified_raw = 0         # matches before the keyword exclusion
        self.role_member = {}          # name -> count
        self.role_free_definition = {} # name -> count, no trailing `;`
        self.role_free_declaration = {}# name -> count, trailing `;`
        self.role_files = set()
        self.macros = set()
        self.renaming_macros = set()   # object-like macros expanding to one identifier
        self.macro_as_class = set()
        self.macro_renaming_class = set()  # the fixture's shape exactly
        self.macro_used = set()
        self.macro_used_files = set()
        self.macro_files = set()
        self.macro_renaming_files = set()
        self.export_sites = 0
        self.export_files = set()
        self.files = 0
        self.bytes = 0
        self.components = set()

    def scan(self, path, component, root):
        self.files += 1
        raw = path.read_bytes()
        self.bytes += len(raw)
        # `relative_to(root)` already starts with the component directory name, which
        # is the repository's short slug -- the same key a report's candidate uses.
        key = path.relative_to(root).as_posix()
        text = raw.decode('utf-8', errors='replace')
        for line in text.splitlines():
            for match in PARCEL_BINDING.finditer(line):
                if match.group(1):
                    self.parcel_const += 1
                    self.parcel_const_files.add(key)
                else:
                    self.parcel_ref += 1
                self.parcel_files.add(key)
            definition = QUALIFIED_DEF.match(line)
            if definition:
                if KEYWORD_LED.match(line):
                    self.qualified_raw += 1
                else:
                    owner, name = definition.group(2), definition.group(3)
                    self.qualified_defs.setdefault(name, set()).add(owner)
                    if name in self.role_names:
                        self.role_member[name] = self.role_member.get(name, 0) + 1
                        self.role_files.add(key)
            elif not line.lstrip().startswith('#'):
                free = FREE_DEF.match(line)
                if free and free.group(1) in self.role_names:
                    name = free.group(1)
                    if line.rstrip().endswith(';'):
                        target = self.role_free_declaration
                    else:
                        target = self.role_free_definition
                        self.role_files.add(key)
                    target[name] = target.get(name, 0) + 1
            declaration = CLASS_DECL.match(line)
            if declaration and declaration.group(1) in self.macros:
                self.macro_as_class.add(declaration.group(1))
                self.macro_files.add(key)
                if declaration.group(1) in self.renaming_macros:
                    self.macro_renaming_class.add(declaration.group(1))
                    self.macro_renaming_files.add(key)
            for use in QUALIFIED_USE.finditer(line):
                if use.group(1) in self.macros:
                    self.macro_used.add(use.group(1))
                    self.macro_used_files.add(key)
            for call in EXPORT_CALLS:
                if call + '(' in line:
                    self.export_sites += 1
                    self.export_files.add(key)

    def ambiguous_names(self):
        return sorted(name for name, owners in self.qualified_defs.items()
                      if len(owners) > 1)


def census_sources(roots):
    roles = reviewed_names()
    shapes = Shapes(roles)
    per_root = {}
    for root in roots:
        before = shapes.files
        components = sorted(p for p in root.iterdir() if p.is_dir())
        for component in components:
            shapes.components.add(component.name)
        # The macro-name table is built first, over the whole corpus, so the shape
        # question is order independent: with a single pass, a `class Stub` in a file
        # walked before the header that defines the macro would not be counted, and
        # the answer here is a 0 that a walk order could have produced.
        for component in components:
            for path in source_files(component):
                for line in path.read_bytes().decode('utf-8', errors='replace').splitlines():
                    macro = OBJECT_MACRO.match(line)
                    if macro:
                        shapes.macros.add(macro.group(1))
                        if SINGLE_IDENTIFIER.match(macro.group(2)):
                            shapes.renaming_macros.add(macro.group(1))
        for component in components:
            for path in source_files(component):
                shapes.scan(path, component, root)
        per_root[root] = shapes.files - before
    return roles, shapes, per_root


def census_reports(trees):
    """What the saved reports carry, and what they demonstrably do not."""
    rows = {}
    limitation_strings = {}
    token_hits = []
    duplicates = 0
    for tree in trees:
        for component in sorted(p for p in tree.iterdir() if p.is_dir()):
            report = component / 'report.json'
            if not report.exists():
                continue
            doc = json.loads(report.read_text())
            identity = (doc.get('repository'), doc.get('commit'))
            if identity in rows:
                # The two saved trees overlap; counting the same run twice would
                # inflate every per-report tally below, so the duplicate is skipped
                # entirely rather than re-counted and then de-duplicated.
                duplicates += 1
                continue
            per_rule = {}
            analysis_status = {}
            parse_status = {}
            passes = {}
            files = {}
            bad_lines = 0
            for candidate in doc.get('candidates', ()):
                per_rule[candidate['rule_id']] = per_rule.get(candidate['rule_id'], 0) + 1
                for counter, value in ((analysis_status, candidate.get('file_analysis_status')),
                                       (parse_status, candidate.get('file_parse_status')),
                                       (passes, ','.join(candidate.get('passes', ())))):
                    counter[value] = counter.get(value, 0) + 1
                key = '%s/%s' % (component.name, candidate['file'])
                files[key] = files.get(key, 0) + 1
                if not isinstance(candidate.get('line'), int) or candidate['line'] < 1:
                    bad_lines += 1
            limitations = doc.get('limitations', ())
            for item in limitations:
                limitation_strings[item] = limitation_strings.get(item, 0) + 1
                for token in CASE_TOKENS:
                    if token in item:
                        token_hits.append((component.name, token, item[:120]))
            rows[identity] = {
                'tree': tree.name,
                'component': component.name,
                'repository': identity[0],
                'commit': identity[1],
                'candidates': len(doc.get('candidates', ())),
                'per_rule': per_rule,
                'candidate_files': files,
                'distinct_files': len(files),
                'analysis_status': analysis_status,
                'parse_status': parse_status,
                'passes': passes,
                'candidates_without_a_valid_line': bad_lines,
                'limitations': len(limitations),
                'shards_blocked': sum(1 for run in doc.get('coverage', {})
                                      .get('run_state', {}).get('pass_runs', ())
                                      if run.get('detector_status') == 'blocked'),
            }
    return list(rows.values()), limitation_strings, token_hits, duplicates


def print_sources(roles, shapes, per_root):
    print('== A. source-shape census')
    print('policy read: %s sha256 %s' % (MODELS.name, sha256_of(MODELS)))
    print('reviewed caller-role names: %d' % len(roles))
    for name, kind in roles:
        print('    %-28s %s' % (name, kind))
    print('files scanned: %d (%d bytes) over %d corpora'
          % (shapes.files, shapes.bytes, len(per_root)))
    for root, count in per_root.items():
        print('    %-34s %d files' % (root.name, count))
    print()
    print('S1 entry parcel binding')
    total = shapes.parcel_const + shapes.parcel_ref
    print('    %-34s %d' % ('const MessageParcel &', shapes.parcel_const))
    print('    %-34s %d' % ('MessageParcel & (mutable)', shapes.parcel_ref))
    print('    %-34s %d in %d files'
          % ('both forms together', total, len(shapes.parcel_files)))
    print('    %-34s %d files' % ('files with a const form at all',
                                  len(shapes.parcel_const_files)))
    print()
    print('S2 ambiguous callee name (one name, more than one defining owner)')
    ambiguous = shapes.ambiguous_names()
    # The definition shape `Type Owner::Name(` also matches a static data member's
    # definition (`const std::string DistributedWant::ACTION_HOME("...")`), which is
    # never a callee. Real OpenHarmony method names are camel case with no underscore,
    # so the narrower row is the better proxy for "a name that can be called".
    camel = [n for n in ambiguous if any(c.islower() for c in n) and '_' not in n]
    print('    %-34s %d' % ('distinct defined owners::names', sum(
        len(v) for v in shapes.qualified_defs.values())))
    print('    %-34s %d' % ('distinct defined names', len(shapes.qualified_defs)))
    print('    %-34s %d' % ('names with >= 2 owners', len(ambiguous)))
    print('    %-34s %d' % ('  of those, camel case with no underscore', len(camel)))
    print('    %-34s %d' % ('qualified-call lines excluded as not definitions',
                            shapes.qualified_raw))
    for name in camel[:8]:
        owners = sorted(shapes.qualified_defs[name])
        print('        %-30s %d owners: %s' % (name, len(owners), ', '.join(owners[:4])))
    print()
    print('S3 reviewed caller-role name defined in the scanned sources')
    print('    %-34s %d' % ('member definitions (`Owner::Name`)',
                            sum(shapes.role_member.values())))
    print('    %-34s %d' % ('file-scope definitions (no trailing `;`)',
                            sum(shapes.role_free_definition.values())))
    print('    %-34s %d' % ('file-scope declarations (trailing `;`)',
                            sum(shapes.role_free_declaration.values())))
    print('    %-34s %d' % ('files with member or free definition',
                            len(shapes.role_files)))
    for name in shapes.role_names:
        member = shapes.role_member.get(name, 0)
        free = shapes.role_free_definition.get(name, 0)
        declared = shapes.role_free_declaration.get(name, 0)
        if member or free or declared:
            print('        %-30s member %d  file-scope-def %d  decl %d'
                  % (name, member, free, declared))
    print()
    print('S4 object-like macro used as a class name')
    print('    %-34s %d' % ('object-like macros defined', len(shapes.macros)))
    print('    %-34s %d' % ('  expanding to a single identifier',
                            len(shapes.renaming_macros)))
    print('    %-34s %d in %d files'
          % ('also used as `Name::` anywhere', len(shapes.macro_used),
             len(shapes.macro_used_files)))
    print('    %-34s %d' % ('also declared as `class`/`struct`',
                            len(shapes.macro_as_class)))
    print('    %-34s %d files' % ('files involved', len(shapes.macro_files)))
    print('    %-34s %d (%d files)'
          % ("the fixture's shape: renaming macro as a class name",
             len(shapes.macro_renaming_class), len(shapes.macro_renaming_files)))
    for name in sorted(shapes.macro_as_class):
        tag = 'renaming' if name in shapes.renaming_macros else 'expansion has more than one token'
        print('        %-24s %s' % (name, tag))
    print()
    print('S5 capability export call sites')
    print('    %-34s %d in %d files'
          % ('/'.join(EXPORT_CALLS), shapes.export_sites, len(shapes.export_files)))


def print_reports(rows, limitation_strings, token_hits, duplicates):
    print()
    print('== B. saved-report census')
    print('distinct (repository, commit) reports: %d; duplicate report files skipped: %d'
          % (len(rows), duplicates))
    total = sum(r['candidates'] for r in rows)
    print('candidates: %d; components with none: %d'
          % (total, sum(1 for r in rows if r['candidates'] == 0)))
    print('candidates whose stored line is not an int >= 1: %d'
          % sum(r['candidates_without_a_valid_line'] for r in rows))
    print('components with a blocked shard: %d'
          % sum(1 for r in rows if r['shards_blocked']))
    per_rule = {}
    for row in rows:
        for rule, count in row['per_rule'].items():
            per_rule[rule] = per_rule.get(rule, 0) + count
    catalogue = [
        'ipc.relay.descriptor-boundary', 'ipc.auth.missing', 'ipc.auth.caller-class',
        'ipc.auth.object-owner', 'ipc.auth.identity-domain', 'ipc.auth.service-identity',
        'ipc.auth.request-identity', 'ipc.auth.guard-coverage', 'ipc.parcel.copy-range',
        'ipc.parcel.position-underflow', 'ipc.capability.export']
    print('per rule, with the catalogue rules that scored zero named:')
    for rule in sorted(set(per_rule) | set(catalogue)):
        count = per_rule.get(rule, 0)
        print('    %-32s %d%s' % (rule, count, '   (zero)' if count == 0 else ''))
    def spread(counter):
        merged = {}
        for row in rows:
            for key, count in row[counter].items():
                merged[key] = merged.get(key, 0) + count
        return merged
    for label, counter in (('file_analysis_status', 'analysis_status'),
                           ('file_parse_status', 'parse_status'),
                           ('passes', 'passes')):
        print('%s: %s' % (label, json.dumps(spread(counter), sort_keys=True)))
    print()
    print('limitations: %d distinct strings over %d reports'
          % (len(limitation_strings), len(rows)))
    for text in sorted(limitation_strings):
        print('    x%-4d %s' % (limitation_strings[text], text[:110]))
    print()
    print('case-level sentences in the saved reports: %d' % len(token_hits))
    for name, token, sample in token_hits[:10]:
        print('    %s %s %s' % (name, token, sample))
    if not token_hits:
        print('    none of [%s] reaches a saved report' % ', '.join(CASE_TOKENS))


def planned_paths(rows):
    """`component -> the repo-relative paths the run planned to read`.

    Read back out of the reports' scope plans, so part D tests the shape sets against
    what the run itself said it covered instead of against a second copy of the
    exclusion list that could drift from it.
    """
    planned = {}
    for row in rows:
        path = Path('/home/audit/wtmp/ipc-audit-all') / row['component'] / 'report.json'
        if not path.exists():
            path = Path('/home/audit/wtmp/ipc-audit-bline') / row['component'] / 'report.json'
        if not path.exists():
            continue
        doc = json.loads(path.read_text())
        names = set()
        for shard in doc.get('scope', {}).get('shards', ()):
            names.update(shard.get('paths', ()))
        planned[row['component']] = names
    return planned


def print_scope(rows, shapes):
    print()
    print('== D. were the shape files inside the scope the run planned?')
    planned = planned_paths(rows)
    sets = [('S1 parcel binding, const form', shapes.parcel_const_files),
            ('S3 local reviewed caller-role name', shapes.role_files),
            ('S4 object-like macro as a class name', shapes.macro_files),
            ('S5 capability export call site', shapes.export_files)]
    for label, paths in sets:
        inside = outside = unplanned = 0
        for key in paths:
            component, _, relative = key.partition('/')
            names = planned.get(component)
            if names is None:
                unplanned += 1
            elif relative in names:
                inside += 1
            else:
                outside += 1
        print('    %-38s in the saved plan %d, in scope of a report that does not '
              'name it %d, component has no saved report here %d'
              % (label, inside, outside, unplanned))


def print_overlap(rows, shapes):
    print()
    print('== C. candidates that sit in the files part A found the shape in')
    sets = [('S1 parcel binding of either form', shapes.parcel_files),
            ('S1 parcel binding, const form', shapes.parcel_const_files),
            ('S3 local reviewed caller-role name', shapes.role_files),
            ('S4 object-like macro as a class name', shapes.macro_files),
            ("S4 renaming macro as a class name", shapes.macro_renaming_files),
            ('S5 capability export call site', shapes.export_files)]
    total = sum(r['candidates'] for r in rows)
    print('candidates considered: %d over %d reports' % (total, len(rows)))
    joined = [r for r in rows if r['component'] in shapes.components]
    print('reports whose component has a corpus tree here: %d of %d, carrying %d of %d '
          'candidates; the rest cannot be joined against a tree this run can read'
          % (len(joined), len(rows), sum(r['candidates'] for r in joined), total))
    for label, paths in sets:
        hit = 0
        seen = set()
        components = {}
        for row in rows:
            for key, count in row['candidate_files'].items():
                if key in paths:
                    hit += count
                    seen.add(key)
                    components[row['component']] = components.get(row['component'], 0) + count
        spread = ', '.join('%s %d' % pair for pair in
                           sorted(components.items(), key=lambda kv: (-kv[1], kv[0]))[:5])
        print('    %-38s %d candidates in %d of the %d corpus files%s'
              % (label, hit, len(seen), len(paths), (' [' + spread + ']') if spread else ''))
    # A zero is only informative next to where the shape's files live, so the shape
    # sets are also reported by the component that owns them.
    print()
    print('components the shape sets live in, for reading the zeros above:')
    for label, paths in sets[:1] + sets[2:3] + sets[4:5]:
        owners = {}
        for key in paths:
            owners[key.split('/')[0]] = owners.get(key.split('/')[0], 0) + 1
        top = sorted(owners.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
        print('    %-38s %s' % (label, ', '.join('%s %d' % pair for pair in top)))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--root', action='append', default=None,
                        help='parent of one corpus component per subdirectory')
    parser.add_argument('--reports', action='append', default=None,
                        help='parent of one saved report per component subdirectory')
    args = parser.parse_args()
    roots = tuple(Path(p) for p in (args.root or DEFAULT_ROOTS))
    trees = tuple(Path(p) for p in (args.reports or DEFAULT_REPORTS))
    roles, shapes, per_root = census_sources(roots)
    rows, limitation_strings, token_hits, duplicates = census_reports(trees)
    print_sources(roles, shapes, per_root)
    print_reports(rows, limitation_strings, token_hits, duplicates)
    print_overlap(rows, shapes)
    print_scope(rows, shapes)


if __name__ == '__main__':
    main()
