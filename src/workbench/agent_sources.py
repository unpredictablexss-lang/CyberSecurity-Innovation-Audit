"""Verified reads from fixed Git blobs and tracked source archives, without extraction."""
import hashlib
from . import service
from src.ohscanner.git_source import load_git_sources


class FixedSourceReader:
    def __init__(self, settings, store, job, report):
        self.settings, self.store, self.job, self.report = settings, store, job, report
        self.entries = {item['file']: item for item in (report.get('_workbench', {}).get('source_inventory') or []) if isinstance(item, dict) and isinstance(item.get('file'), str)}
        self.archive_path = None
        self.members = {}

    def read(self, file):
        service.safe_relative_path(file)
        entry = self.entries.get(file)
        if entry is None:
            raise ValueError('file is outside the scanned source inventory')
        binding = entry.get('archive_binding')
        if not isinstance(binding, dict):
            return service.source(self.settings, self.store, self.job, file)
        archive_path = binding.get('archive_path')
        if not isinstance(archive_path, str):
            raise ValueError('source archive path binding is malformed')
        service.safe_relative_path(archive_path)
        if self.job.get('spec', {}).get('commit') != self.report.get('commit'):
            raise ValueError('source archive commit binding mismatch')
        if self.archive_path != archive_path:
            repo = self.store.repository(self.job['repository_id'])
            root = service.check_repository(self.settings, repo['path'])
            _, tree, sources, _ = load_git_sources(root, self.report['commit'], (archive_path,))
            expected_tree = self.job.get('spec', {}).get('git_tree') or self.report.get('git_tree')
            if not expected_tree or tree != expected_tree:
                raise ValueError('source archive tree binding mismatch')
            # Cache only one bounded archive per investigation-tool session.
            self.members = {item.path: item for item in sources if item.archive_binding}
            self.archive_path = archive_path
        member = self.members.get(file)
        if member is None or member.archive_binding != binding:
            raise ValueError('source archive member differs from committed scan inventory')
        digest = hashlib.sha256(member.data).hexdigest()
        if digest != entry.get('sha256') or member.oid != entry.get('blob'):
            raise ValueError('source archive member hash or identity mismatch')
        return {'file': file, 'commit': self.report['commit'], 'blob': None,
                'sha256': digest, 'text': member.data.decode('utf-8'), 'archive_binding': binding}