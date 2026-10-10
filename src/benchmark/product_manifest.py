"""Read product manifests and validate a partial, source-bound experiment lock."""

import hashlib
import re
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath


def relative_path(value):
    path = PurePosixPath(value)
    if not value or path.is_absolute() or '..' in path.parts or '\\' in value or ':' in value:
        raise ValueError('Unsafe manifest path: ' + value)
    return path.as_posix()


def read_manifest(root, entry='default.xml'):
    root = root.resolve()
    documents, remotes, defaults, projects = {}, {}, {}, []
    paths = set()

    def visit(relative, stack):
        relative = relative_path(relative)
        if relative in stack:
            raise ValueError('Manifest include cycle')
        if relative in documents:
            raise ValueError('Repeated manifest include is ambiguous')
        file = (root / relative).resolve()
        if not file.is_relative_to(root):
            raise ValueError('Manifest include escapes root')
        data = file.read_bytes()
        if b'<!DOCTYPE' in data or b'<!ENTITY' in data:
            raise ValueError('Manifest entity declarations are unsupported')
        document = ET.fromstring(data)
        if document.tag != 'manifest':
            raise ValueError('Expected repo manifest XML')
        documents[relative] = hashlib.sha256(data).hexdigest()
        for node in document:
            if node.tag == 'remote':
                name, fetch = node.attrib['name'], node.attrib['fetch'].rstrip('/')
                if not fetch.startswith('https://'):
                    raise ValueError('Manifest remote must use HTTPS')
                if name in remotes and remotes[name] != fetch:
                    raise ValueError('Conflicting remote definitions')
                remotes[name] = fetch
            elif node.tag == 'default':
                for key in ('remote', 'revision'):
                    if key in node.attrib:
                        if key in defaults and defaults[key] != node.attrib[key]:
                            raise ValueError('Conflicting manifest defaults')
                        defaults[key] = node.attrib[key]
            elif node.tag == 'include':
                visit(node.attrib['name'], stack + [relative])
            elif node.tag == 'project':
                record = dict(node.attrib)
                path = relative_path(record.get('path', record['name']))
                if path in paths:
                    raise ValueError('Duplicate manifest project path')
                paths.add(path)
                record['path'] = path
                record['file_operations'] = []
                for child in node:
                    if child.tag not in ('linkfile', 'copyfile'):
                        raise ValueError('Unsupported project operation: ' + child.tag)
                    record['file_operations'].append(dict(kind=child.tag,
                        src=relative_path(child.attrib['src']), dest=relative_path(child.attrib['dest'])))
                projects.append(record)
            elif node.tag not in ('notice', 'repo-hooks', 'manifest-server', 'superproject', 'contactinfo'):
                raise ValueError('Unsupported manifest directive: ' + node.tag)

    visit(entry, [])
    for project in projects:
        remote = project.get('remote', defaults.get('remote'))
        revision = project.get('revision', defaults.get('revision'))
        if remote not in remotes or not revision:
            raise ValueError('Unresolved project remote/revision')
        project.update(remote=remote, revision=revision,
                       fetch_url=remotes[remote] + '/' + project['name'] + '.git')
    return dict(entry=entry, documents=documents, projects=projects)


def select_projects(manifest, names):
    selected = []
    for name in names:
        matches = [item for item in manifest['projects'] if item['name'] == name]
        if len(matches) != 1:
            raise ValueError('Missing or ambiguous manifest project: ' + name)
        selected.append(matches[0])
    return selected


def bind_resolution(project, resolution):
    if resolution['fetch_url'].rstrip('/') != project['fetch_url'].rstrip('/'):
        raise ValueError('Resolution comes from a different manifest remote')
    if resolution['revision'] != project['revision']:
        raise ValueError('Resolution revision does not match manifest')
    if not re.fullmatch(r'[0-9a-f]{40}', resolution['commit']):
        raise ValueError('Resolution requires a full commit SHA')
    revision = project['revision']
    if re.fullmatch(r'[0-9a-f]{40}', revision) and revision != resolution['commit']:
        raise ValueError('Pinned manifest commit differs from resolution')
    if resolution.get('resolved_ref') != ('refs/heads/' + revision if not re.fullmatch(r'[0-9a-f]{40}', revision) else revision):
        raise ValueError('Explicit resolved ref is missing or mismatched')
    return dict(project, resolved_commit=resolution['commit'], resolved_ref=resolution['resolved_ref'],
                resolution_status='resolved')
