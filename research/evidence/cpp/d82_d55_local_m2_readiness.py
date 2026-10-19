from __future__ import annotations
import argparse, hashlib, json, subprocess, sys
from pathlib import Path


def strict_load(path: Path):
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError(f'duplicate JSON key {k!r} in {path}')
            out[k] = v
        return out
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=pairs)


def sha(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_show(root: Path, spec: str) -> bytes:
    return subprocess.run(['git','-C',str(root),'show',spec],check=True,stdout=subprocess.PIPE).stdout


def parse_bytes(data: bytes, label: str):
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out: raise ValueError(f'duplicate JSON key {k!r} in {label}')
            out[k] = v
        return out
    return json.loads(data.decode('utf-8'), object_pairs_hook=pairs)


def advisory_summary(path: Path, batch: str):
    d = strict_load(path)
    entries = d['entries']
    result = []
    for e in entries:
        cve = e.get('cve') or e.get('cve_id')
        snapshot = e.get('snapshot') or {}
        status = e.get('status') or e.get('snapshot_status')
        body_rel = snapshot.get('body_file') or e.get('response_body_file')
        digest = snapshot.get('body_sha256') or e.get('immutable_response_bytes_sha256')
        body_ok = None
        body_bytes = None
        if body_rel and digest:
            body_path = path.parent / body_rel
            if body_path.exists():
                body_bytes = body_path.stat().st_size
                body_ok = sha(body_path) == digest
            else:
                body_ok = False
        result.append({
            'cve': cve, 'status': status, 'publisher': e.get('publisher'),
            'canonical_url': e.get('canonical_url'), 'source_version_scope_present': bool(e.get('source_version_scope')),
            'body_file': body_rel, 'declared_body_sha256': digest, 'body_bytes': body_bytes,
            'body_hash_verified': body_ok,
            'scope_status': e.get('scope_status'),
        })
    return {'manifest': str(path), 'manifest_sha256': sha(path), 'entry_count': len(entries), 'entries': result}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[3])
    ap.add_argument('--advisory-a-root', type=Path)
    ap.add_argument('--advisory-b-root', type=Path)
    ap.add_argument('--out-dir', type=Path)
    a = ap.parse_args()
    root = a.root.resolve()
    sibling = root.parent
    aroot = (a.advisory_a_root or sibling / 'd55-cve-advisories-a-20261021').resolve()
    broot = (a.advisory_b_root or sibling / 'd55-cve-advisory-b-20261021').resolve()
    out = (a.out_dir or root / 'research/evidence/cpp').resolve()
    out.mkdir(parents=True, exist_ok=True)

    protocol = root / 'research/data_sensitive/D55_HOLDOUT_PROTOCOL_20261021.json'
    prereg = root / 'research/data_sensitive/D55_INDEPENDENT_HOLDOUT_PREREGISTRATION.md'
    execution = root / 'research/data_sensitive/D55_HOLDOUT_EXECUTION_TASK.md'
    d41m = root / 'research/data_sensitive/D41_HOLDOUT_MANIFEST.json'
    d41r = root / 'research/data_sensitive/D41_HOLDOUT_RESULTS.json'
    d41md = root / 'research/data_sensitive/D41_HOLDOUT_RESULTS.md'
    d41packet = root / 'research/data_sensitive/D41_BLIND_REVIEW_PACKET.json'
    d48reg = root / 'research/data_sensitive/D48_HOLDOUT_PREREGISTRATION.md'
    d48readme = root / 'research/data_sensitive/D48_HOLDOUT/distributed_screen/README.md'
    d48summary = root / 'research/data_sensitive/D48_HOLDOUT/distributed_screen/summary.json'
    d48first = root / 'research/data_sensitive/D48_HOLDOUT/distributed_screen/first.json'
    d48replay = root / 'research/data_sensitive/D48_HOLDOUT/distributed_screen/replay.json'
    inputs = [protocol, prereg, execution, d41m, d41r, d41md, d41packet, d48reg, d48readme, d48summary, d48first, d48replay]
    for p in inputs:
        if not p.is_file(): raise FileNotFoundError(p)
    proto = strict_load(protocol)
    m41 = strict_load(d41m); r41 = strict_load(d41r); packet41 = strict_load(d41packet)
    s48 = strict_load(d48summary)
    d55_missing = proto.get('current_missing_inputs', [])
    t54_bytes = git_show(root, 'b4537212b:research/evidence/cpp/T54_D55_PROTOCOL_REVIEW_C86E0B_20261021.json')
    t54 = parse_bytes(t54_bytes, 'T54 final acceptance')
    t55_bytes = git_show(root, '233da2384:research/evidence/cpp/T55_D55_ADVISORY_MANIFEST_ACCEPTANCE_20261021.json')
    t55 = parse_bytes(t55_bytes, 'T55 advisory acceptance')
    t55rev_bytes = git_show(root, '6d65b5220:research/evidence/cpp/T55_D55_ADVISORY_BATCH_B_REVISION_ACCEPTANCE_20261021.json')
    t55rev = parse_bytes(t55rev_bytes, 'T55 batch B revision acceptance')

    apath = aroot / 'research/data_sensitive/d55_cve_advisories_a/D55_CVE_ADVISORIES_A_20261019.json'
    bpath = broot / 'research/data_sensitive/D55_KNOWN_CVE_ADVISORY_BATCH_B_20261019/D55_KNOWN_CVE_ADVISORY_BATCH_B_20261019.json'
    adv_a = advisory_summary(apath, 'A'); adv_b = advisory_summary(bpath, 'B')
    target_ids = set(proto['known_cve_universe']['identifiers'])
    observed_ids = {x['cve'] for x in adv_a['entries'] + adv_b['entries']}
    hash_verified = [x for x in adv_a['entries'] + adv_b['entries'] if x['body_hash_verified'] is True]
    body_missing = [x['cve'] for x in adv_a['entries'] + adv_b['entries'] if x['body_hash_verified'] is not True]

    repos41 = m41.get('repositories', [])
    source_names = [x.get('repository') for x in repos41]
    labels41 = m41.get('label_protocol', {}).get('current_independent_labels', 0)
    files41 = r41.get('scope_file_count')
    counts48 = s48.get('coverage_counts') or s48.get('source_parsing', {}).get('parsing_status') or {}
    sample48 = {
        'repository': s48.get('repository'), 'commit': s48.get('commit'), 'tree': s48.get('tree'),
        'task_status': s48.get('task_status'), 'detector_status': s48.get('detector_status'),
        'candidate_count': s48.get('candidate_count'), 'eligible_files': s48.get('eligible_files') or s48.get('scope', {}).get('source_files'),
        'coverage_counts': counts48, 'independent_label_evidence': 'none recorded in inspected D48 protocol/readme/report artifacts'
    }
    sample48.update({'pinned_source_commit_from_readme': '373e2b5241c0e5dcb923642059ae83e4e9a1a64e', 'eligible_files_from_readme': 97,
                     'all_files_partial_from_readme': True, 'all_scans_blocked_from_readme': True})

    d55_campaign = root / 'research/data_sensitive/D55_HOLDOUT'
    campaign_files = []
    if d55_campaign.exists(): campaign_files = [p.relative_to(root).as_posix() for p in d55_campaign.rglob('*') if p.is_file()]
    labels_created = proto.get('labels_created', proto.get('accuracy_evaluation_started', None))
    approvals = {
        'threshold_owner_approval': 'absent: protocol and T54 acceptance both say proposed thresholds pending D-owner approval',
        'source_cohort_owner_or_eligibility_approvals': 'absent: no frozen frame/cohort or row-level eligibility approver records in inspected D55 materials',
        'two_independent_reviewer_assignments_and_conflict_declarations': 'absent: required by protocol, not assigned in inspected records',
        'independent_adjudicator_assignment': 'absent: required by protocol, not assigned in inspected records',
        'prediction_key_custodian_and_approved_immutable_storage': 'absent: required custody/storage is listed as missing; no D55 sealed key/custody record',
        'scanner_freeze_manifest': 'absent: required full scanner/model/profile/parser/config/scope freeze is missing; no campaign freeze manifest',
    }
    blockers = [
      {'gate':'approved_thresholds','state':'blocked','repo_self_service':'can preserve proposed defaults and verify missing approval','required_external_actor':'D owner must approve/replace thresholds before frame selection and label access','evidence':['D55 protocol pre_registered_decision_thresholds.status','T54 execution_inputs_missing']},
      {'gate':'independent_sampling_frame_and_cohort','state':'blocked','repo_self_service':'can enumerate local Git objects and produce hashes/exclusion candidates; cannot designate an independent inventory or probability frame from scanner-team authored corpus','required_external_actor':'independent source inventory/custodian plus source-family provenance and eligibility approver','evidence':['D55 current_missing_inputs: independent source inventory and frozen sampling frame','D55 protocol sampling.frame requirements']},
      {'gate':'prior_use_overlap_and_exclusions','state':'partial_inventory_only','repo_self_service':'can hash and compare repo/path/blob identities against specified D records and full D history once inventory is supplied','required_external_actor':'source steward resolves modified vendor derivation and signs unresolved cases before scan','evidence':['D55 protocol source_identity_and_deduplication','D41 manifest/results','D48 protocol/results']},
      {'gate':'reproducible_selection_and_seed','state':'blocked','repo_self_service':'can implement seeded stratified selector after frame and strata are frozen','required_external_actor':'independent frame owner supplies frame; seed commitment must be frozen before scan and labels','evidence':['D55 current_missing_inputs: pre-scan selection record, inclusion probabilities, and seed record']},
      {'gate':'planning_simulation','state':'blocked','repo_self_service':'can run simulation after approved thresholds, independent frame/cluster distribution, plausible external prevalence/DEFF and label completion inputs are supplied','required_external_actor':'owner/reviewer approves assumptions; source steward supplies frame inputs','evidence':['D55 current_missing_inputs: pre-label precision planning simulation','D55 protocol sampling.planning_formula_inputs']},
      {'gate':'scanner_and_scope_freeze','state':'blocked','repo_self_service':'can compute clean-checkout and component hashes once target evaluation version is designated','required_external_actor':'D scanner owner freezes exact version; independent verifier signs manifest','evidence':['D55 current_missing_inputs: frozen scanner bundle and scope hashes','T54 execution_inputs_missing']},
      {'gate':'known_cve_advisory_package','state':'partial_not_ready','repo_self_service':'can verify all captured bytes, manifest IDs, and append hashes for already captured snapshots','required_external_actor':'authorized network/source access to capture blocked primary GHSA responses; adjudicator resolves version-scope ambiguities before scoring','evidence':['T55 evidence_status/status_decision','T55 revision acceptance','A/B manifests']},
      {'gate':'finding_matcher_and_coverage_aggregation','state':'blocked','repo_self_service':'can implement and hash versioned matcher/aggregation after source reference and frozen scanner outputs are available','required_external_actor':'D owner approves claim-level matching rules before labels/unblinding','evidence':['D55 current_missing_inputs: versioned frozen candidate-to-reference matcher; frozen coverage/unknown aggregation implementation']},
      {'gate':'independent_labels_and_adjudication','state':'blocked','repo_self_service':'can create blinded packets after frozen scan; cannot create human labels','required_external_actor':'two qualified independent reviewers and independent adjudicator provide frozen, source-bound labels/conflict declarations','evidence':['D55 labels_created=false','T54 execution_inputs_missing','D41 labels=0','D48 no labels']},
      {'gate':'sealed_prediction_custody','state':'blocked','repo_self_service':'can hash output package and prepare manifest','required_external_actor':'independent custodian provides approved immutable access-controlled storage and access log','evidence':['D55 current_missing_inputs: approved immutable storage for sealed predictions and separated labels']},
    ]
    exclusions = [
      {'source_group':'D41 six-repository replay and 99-case packet','decision':'exclude from D55 scoring','reason':'scanned post selection; detector 0.17.0; no independent labels; post-scan stratified 99-case packet; protocol explicitly excludes D41','repositories':source_names,'eligible_files':files41,'candidate_observations':r41.get('total_candidate_count'),'independent_labels':labels41,'coverage':r41.get('aggregate_coverage_counts')},
      {'source_group':'D48 distributed_screen snapshot','decision':'exclude from D55 scoring','reason':'convenience sample; D48 prior inspected/replayed; blocked scan; all 97 files partial; zero labels; protocol explicitly excludes D48','repository':'openharmony/distributed_screen','commit':'373e2b5241c0e5dcb923642059ae83e4e9a1a64e','eligible_files':97,'independent_labels':0},
      {'source_group':'D49-D50 component/CVE replay records','decision':'exclude from D55 scoring','reason':'protocol classifies as already reviewed component/CVE replay and rule-development examples; targeted, partial/blocked, not independent probability sample'},
      {'source_group':'D51-D53 Pasteboard records and T51-T53 acceptance','decision':'exclude from D55 scoring','reason':'protocol explicitly classifies as targeted candidate/config investigations and development material, not prevalence sample'},
      {'source_group':'D35-D50 development/regression/fixtures/PoCs/rule-tuning material','decision':'exclude overlapping source units from D55 scoring','reason':'protocol says any D-visible or tuned item is development data; exact raw blob/content overlap excludes regardless of path/commit; unresolved modified vendor derivative blocks stratum'},
      {'source_group':'D48_PANEL_SMOKE/d48-d43-positive-control','decision':'exclude from D55 scoring','reason':'explicit positive-control smoke artifact; scanner-development control rather than independent source sample'},
    ]
    matrix = {
      'schema_version':1,'record_id':'D82-D55-LOCAL-M2-BLOCKER-MATRIX-20261020','status':'STOP_BEFORE_FRAME_SELECTION_AND_SCAN','m2_status':'NOT_MET','accuracy_metrics':'not_estimable_no_labels_or_valid_cohort','m3_status':'not_assessed_by_this_inventory',
      'scope':{'checkout':str(root),'script_sha256':sha(Path(__file__).resolve()),'base_commit':subprocess.run(['git','-C',str(root),'rev-parse','HEAD'],check=True,text=True,capture_output=True).stdout.strip(),'inspection_limit':'Only D55 final preregistration/execution task, T54 final acceptance, D41/D48 sample records, and D55 advisory A/B packages were inventoried; no labels, metrics, or holdout cohort were created.'},
      'inputs':{str(p.relative_to(root)).replace('\\','/'):sha(p) for p in inputs},
      't54_final_acceptance':{'commit':'b4537212b','sha256':hashlib.sha256(t54_bytes).hexdigest(),'reviewed_commit':t54.get('reviewed_commit'),'protocol_design_status':t54.get('protocol_design_status'),'execution_status':t54.get('execution_status'),'m2_status':t54.get('m2_status'),'execution_inputs_missing':t54.get('execution_inputs_missing')},
      'd55_protocol_state':{'status':proto.get('status'),'accuracy_evaluation_started':proto.get('accuracy_evaluation_started'),'labels_created':proto.get('labels_created'),'metrics_computed':proto.get('metrics_computed'),'current_missing_inputs':d55_missing,'campaign_evidence_files_present':campaign_files,'approvals_and_freezes':approvals},
      'd41':{'manifest_study_status':m41.get('study_status'),'results_state':d41md.read_text(encoding='utf-8').splitlines()[0:4],'state_reconciliation':'manifest retains preregistered_not_run; later aggregate results and report record an actual two-round replay. Use the results/report for execution occurrence, while the manifest state remains a stale preregistration field.','repository_count':len(repos41),'repositories':source_names,'eligible_files':files41,'candidate_observations':r41.get('total_candidate_count'),'coverage_counts':r41.get('aggregate_coverage_counts'),'independent_label_counts':r41.get('independent_labels'),'post_scan_packet_cases':packet41.get('case_count'),'packet_is_population_sample':False,'packet_used_for_D55':False},
      'd48':sample48,
      'd55_known_cve_advisories':{'target_catalog_count':len(target_ids),'batch_a_count':adv_a['entry_count'],'batch_b_count':adv_b['entry_count'],'unique_id_count':len(observed_ids),'missing_ids':sorted(target_ids-observed_ids),'extra_ids':sorted(observed_ids-target_ids),'captured_primary_bytes_hashes_verified':len(hash_verified),'primary_entries_not_verified_as_captured':body_missing,'batch_a':adv_a,'batch_b':adv_b,'t55_acceptance_commit':'233da2384','t55_acceptance_sha256':hashlib.sha256(t55_bytes).hexdigest(),'t55_status':t55.get('evidence_status'),'t55_m2':t55.get('status_decision',{}).get('m2'),'t55_revision_commit':'6d65b5220','t55_revision_sha256':hashlib.sha256(t55rev_bytes).hexdigest(),'t55_revision_decision':t55rev.get('decision'),'t55_revision_remaining_scope':t55rev.get('unknown_or_limited_scope')},
      'exclusion_ledger':exclusions,'blocker_matrix':blockers,
      'self_service_boundary':{'mechanical_actions_agent_can_do': ['hash local Git source objects and inventories','run strict duplicate-key parsing and byte-hash verification','record known D41/D48 overlap and explicit exclusion rows','implement deterministic selector/matcher/coverage/score tools after the protocol inputs are frozen','compute scanner/source manifest hashes after an exact target scanner version is designated'], 'cannot_self_authorize_or_fabricate':['independent source inventory/cohort provenance','owner approval of thresholds and sampling design','qualified independent reviewer/adjudicator identities and conflict declarations','blind labels or human adjudication','custody/access control for sealed predictions and separated labels','unavailable primary advisory bytes or external source scope resolution','product build evidence for M3']},
      'decision':'Do not start holdout scan or label work from repository-local development corpus. First obtain owner-approved thresholds, independent source inventory/custodian and cohort provenance, independent reviewer/adjudicator and custody assignments, exact scanner evaluation bundle, and resolve the still-missing primary advisory captures/scope. Local repo work can prepare auditable mechanics, but cannot convert existing D41/D48/development examples into a valid D55 holdout.'
    }
    json_path = out / 'D82_D55_LOCAL_M2_BLOCKER_MATRIX_20261020.json'
    md_path = out / 'D82_D55_LOCAL_M2_BLOCKER_MATRIX_20261020.md'
    json_path.write_text(json.dumps(matrix,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
    lines = [
      '# D82 — D55 本地 M2 执行准备 blocker matrix', '',
      f"- 状态：**{matrix['status']}**；M2 **NOT MET**。本清点没有建立 cohort、生成标签或计算指标。",
      f"- 核验 checkout：`{root}`；base commit `{matrix['scope']['base_commit']}`。",
      '- T54 最终验收（reviewed commit `c86e0b0`）：协议设计 `READY_FOR_EXECUTION_PREREQUISITES`；执行 `NOT_READY`；M2 `NOT_MET`。',
      '- D41 状态字段有历史差异：manifest 保留 `preregistered_not_run`，但稍后的 aggregate results / 报告记录了双轮 replay；本清点把 manifest 视为冻结预注册状态、把 results 视为执行事实。仍无标签；6 个仓库、3,820 个 eligible files、201 条候选、0 complete、2,787 partial、1,033 not analyzed、独立标签总数为 0。99-case 包是 post-scan stratified review packet，不能当准确率样本。',
      '- D48 `distributed_screen`：方便样本、97 个文件全部 partial、扫描 blocked、0 candidate、没有独立标签；不能作准确率或安全性样本。',
      '- D55 CVE advisory：17 个 catalog IDs 均有记录；A/B 计 9+8 项，15 份已有响应正文哈希可验证；CVE-2026-33636 和 CVE-2026-46675 的主 GHSA 原始正文仍 blocked。T55 接受报告判 `PARTIAL_NOT_READY`，其后的 B revision 仍判 `NOT_READY`。',
      '', '## 必须排除的历史材料', '',
      '| 样本/材料 | 决策 | 原因 |', '|---|---|---|',
    ]
    for ex in exclusions: lines.append(f"| {ex['source_group']} | {ex['decision']} | {ex['reason']} |")
    lines += ['', '## Blocker matrix', '', '| Gate | 当前状态 | 本地可做 | 需要的授权人/外部输入 |', '|---|---|---|---|']
    for b in blockers: lines.append(f"| {b['gate']} | {b['state']} | {b['repo_self_service']} | {b['required_external_actor']} |")
    lines += ['', '## 本地可自助完成的步骤', '', '- 对给定的只读 Git objects、样本清单和 advisory bytes 重算 commit/tree/blob/SHA-256；运行 duplicate-key 严格 JSON 检查。', '- 以明确提供的独立 frame 运行 overlap/dedup 审核、可复现分层抽样、功效/区间仿真，并冻结 scanner bundle。', '- 生成 blind packet 和评分工具的机械部分；人工评审之前不得生成 labels 或打开预测键。', '', '## 需要人类或外部来源的输入', '', '- D owner 对阈值、抽样设计、冻结 scanner 版本作有记录的批准。', '- scanner 团队之外的独立来源清单和有出处的 cohort/frame；D41、D48 与 D 开发语料不满足这一条件。', '- 两位互相独立且未参与开发/选样/扫描的 reviewer、一位独立 adjudicator、冲突声明，以及隔离预测键的保管员和获批不可变存储。', '- 被网络访问阻断的主 advisory 原始字节和 unresolved version-scope 的权威解释。', '', '## 结论', '', matrix['decision'], '', '机器可读明细、输入 SHA-256 与每条排除记录见同目录 JSON。脚本可从任意 checkout 复跑：', '', '```powershell', 'python research/evidence/cpp/d82_d55_local_m2_readiness.py --root . --advisory-a-root ..\\d55-cve-advisories-a-20261021 --advisory-b-root ..\\d55-cve-advisory-b-20261021', '```', '']
    md_path.write_text('\n'.join(lines),encoding='utf-8',newline='\n')
    print(json_path)
    print(md_path)
    print('SUMMARY',json.dumps({'d41':matrix['d41'],'d48':{k:v for k,v in matrix['d48'].items() if k not in ('coverage_counts',)},'advisory_verified_bodies':len(hash_verified),'advisory_missing':body_missing,'blockers':len(blockers)},ensure_ascii=False))

if __name__ == '__main__': main()
