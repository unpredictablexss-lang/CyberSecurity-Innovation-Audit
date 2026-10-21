"""Shared fixed-source planning, using the platform lane's pure services.

These services have no FastAPI/DB dependency. CLI and Worker use the same plan;
planning does not relax any detector's actual eligibility or evidence gate.
"""
from pathlib import Path
from .detectors.admission import pending_admissions
from .detectors.catalog import build_registry, catalog_metadata, default_detector_ids
from .indexing import prepare_git_context
from .git_source import load_git_sources
from src.workbench.sources import manifest_from_context
from src.workbench.planning import plan_audit, metadata_from_detectors


def approved_metadata():
    rows, instances = [], []
    pending = pending_admissions()
    pending_ids = {row['id'] for row in pending}
    for ident, spec in catalog_metadata().items():
        if spec['kind'] != 'research_candidate' or ident in pending_ids:
            continue
        detector = build_registry((ident,)).detectors()[0]
        rows.append({'id': ident, **spec, 'version': detector.version,
                     'supported_languages': list(detector.supported_languages),
                     'evidence_level': 'candidate/unassessed'})
        instances.append(detector)
    return metadata_from_detectors(rows, instances) + pending


def plan_context(context, tree, inventory, sources, selected_detector_ids=None, execution_budget=None):
    manifest = manifest_from_context(context, tree, inventory, sources)
    return plan_audit(manifest, approved_metadata(),
                      selected_detector_ids=selected_detector_ids,
                      execution_budget=execution_budget)


def preview_plan(repo_dir, repository, commit, includes, selected_detector_ids=None, execution_budget=None):
    selected = (tuple(selected_detector_ids) if selected_detector_ids
                else tuple(default_detector_ids()))
    registry = build_registry(selected)
    requested_facts = tuple(sorted({
        fact for detector in registry.detectors() for fact in detector.required_facts
    }))
    context, tree, inventory, _, sources = prepare_git_context(
        Path(repo_dir), repository, commit, tuple(includes), requested_facts=requested_facts)
    plan = plan_context(context, tree, inventory, sources, selected_detector_ids, execution_budget)
    pinned2, tree2, sources2, inventory2 = load_git_sources(Path(repo_dir), commit, tuple(includes))
    signature = lambda rows: tuple((s.path, s.language, s.oid, s.data) for s in rows)
    if (pinned2 != context.request.commit or tree2 != tree or inventory2 != inventory
            or signature(sources2) != signature(sources)):
        raise ValueError('pinned Git source inventory changed during planning')
    return plan
