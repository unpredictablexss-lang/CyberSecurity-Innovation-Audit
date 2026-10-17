"""Record immutable D3 starting point from Git objects, not current edits."""
import hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[2]
BASE='d64d1787250fdff0f912c2733b2739cf6c78ff51'
def git(*a):return subprocess.check_output(['git',*a],cwd=R)
files=git('ls-tree','-r','--name-only',BASE,'tests/fixtures/data_sensitive').decode().splitlines()
report={'date':'2026-10-17','initial_head':BASE,'initial_branch':'feat/teammate-d-sensitive-exposure-20261017',
 'initial_worktree_status':'clean, verified before edits','remote_pr_head':BASE,'remote_main':'e510c99c67f31ec6c73365f9ab749c79ca6ff0a1',
 'pr':17,'is_draft':True,'pr_reviews':[],'pr_comments':[],'inline_review_comments':[],
 'existing_control_sha256':{p:hashlib.sha256(git('show',BASE+':'+p)).hexdigest() for p in files},
 'old_default_model_sha256':hashlib.sha256(git('show',BASE+':src/ohscanner/detectors/data/models.py')).hexdigest(),
 'initial_tests_from_d2_not_rerun_at_baseline':{'cases':528,'passed':517,'skipped':11},
 'ownership':'D-only four approved paths; no public status/core edit despite older generic AGENTS status request'}
(R/'research/data_sensitive/D3_BASELINE.json').write_text(json.dumps(report,indent=2)+'\n')
print('Recorded',len(files),'old fixture files from exact starting commit')
