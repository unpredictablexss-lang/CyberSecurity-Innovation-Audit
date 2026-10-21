"""C1 syntax feasibility probe; never executes target sources or a detector."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
arguments = argparse.ArgumentParser(description=__doc__)
arguments.add_argument('--deps-path', default='.tmp/pydeps')
arguments.add_argument('--source-dir', default='.tmp/c1-ark-runtime/source')
arguments.add_argument('--output', default='.tmp/c1-ark-runtime/parser_probe_replay.json')
options = arguments.parse_args()
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / options.deps_path))

from importlib.metadata import version
from src.parser.ast import parse_source
from tree_sitter import Language, Parser
import tree_sitter_cpp

manifest = json.loads((Path(__file__).parent / 'source_evidence.json').read_text(encoding='utf-8'))
rows = []
for entry in manifest['sources']:
    path = ROOT / options.source_dir / entry['cache_file']
    if not path.is_file():
        raise SystemExit('BLOCKED: source cache missing; retrieve the exact remote blob first: ' + entry['cache_file'])
    data = path.read_bytes()
    blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    digest = hashlib.sha256(data).hexdigest()
    if blob != entry['blob_oid'] or digest != entry['source_sha256']:
        raise SystemExit('REJECTED: source bytes differ from pinned manifest: ' + entry['cache_file'])
    index = parse_source(data.decode('utf-8'), 'cpp')
    tree = Parser(Language(tree_sitter_cpp.language())).parse(data)
    pending = [tree.root_node]
    targets = []
    while pending:
        node = pending.pop()
        if node.type == 'function_definition':
            declarator = node.child_by_field_name('declarator')
            declaration = data[declarator.start_byte:declarator.end_byte].decode() if declarator else ''
            # A syntax-probe selector for this exact research target, not a security rule.
            if 'BuiltinsTypedArrayStubBuilder::Filter(' in declaration:
                targets.append({
                    'start_line': node.start_point[0] + 1,
                    'end_line': node.end_point[0] + 1,
                    'subtree_has_error': node.has_error,
                    'body_kind': node.child_by_field_name('body').type,
                    'qualified_declarator': declaration,
                })
        pending.extend(reversed(node.named_children))
    rows.append({
        'cache_file': entry['cache_file'], 'blob_oid': blob,
        'source_sha256': digest, 'bytes': len(data),
        'parse_status': index.parse_status, 'parse_issues': index.parse_issues,
        'shared_summary_keys': list(index.to_dict()),
        'ir_dsl_call_count': sum(c.name in {'BRANCH', 'Bind', 'Jump', 'LoopBegin', 'LoopEnd'} for c in index.calls),
        'target_function_subtrees': targets,
    })
report = {
    'experiment_kind': 'syntax_feasibility_probe_not_detector',
    'dependencies': {p: version(p) for p in ('tree-sitter', 'tree-sitter-c', 'tree-sitter-cpp')},
    'sources': rows,
    'limitations': [
        'Parsing a source file is not executing a detector.',
        'Error-free subtrees do not upgrade the file parse status.',
        'No IR control-flow, dominance, object identity, or vulnerability proof is computed.',
        'Cached remote blobs are not verified local Git commit/tree objects.',
    ],
}
output = ROOT / options.output
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report, ensure_ascii=False, indent=2))
