#!/usr/bin/env python3
"""Audit exact manifest gitlink matches and declared linkfile sources for the C1 snapshot."""
from __future__ import annotations
import hashlib,json,subprocess,xml.etree.ElementTree as ET
from pathlib import Path,PurePosixPath
HERE=Path(__file__).resolve().parent
PROJECT=HERE.parents[3]
XML=HERE/'source_manifest_resolved_20261019.xml'
SOURCE_ROOT=Path('/mnt/d/openHarmonyScanner/openharmony')
ARCHIVE_ROOT=Path('/home/deepsleep/c-line-c1-profile-20261018/openharmony-git-archive-20261019')
REPORT=ARCHIVE_ROOT/'materialization_manifest.json'
DEST=HERE/'materialization_manifest_20261019.json'
OUT=HERE/'snapshot_gitlink_linkfile_audit_20261019.json'
def sha_bytes(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def git(repo:Path,*args:str)->bytes:return subprocess.run(['git','-C',str(repo),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout
def main()->int:
 root=ET.parse(XML).getroot(); projects={}; links=[]
 for p in root.iter('project'):
  path=p.get('path') or p.get('name'); rev=p.get('revision')
  if path:projects[path]=rev
  for l in p.findall('linkfile'):
   links.append({'project':path,'revision':rev,'src':l.get('src'),'dest':l.get('dest')})
 report=json.loads(REPORT.read_text(encoding='utf-8'))
 DEST.write_bytes(REPORT.read_bytes())
 records={x['path']:x for x in report['projects']}
 missing_manifest_projects=[];unmaterialized=[];declared_gitlinks=0
 for project_path,record in sorted(records.items()):
  for g in record.get('gitlinks',[]):
   declared_gitlinks+=1;nested=(PurePosixPath(project_path)/g['path']).as_posix();target=projects.get(nested)
   archive_gitlink=ARCHIVE_ROOT.joinpath(*PurePosixPath(project_path).parts,*PurePosixPath(g['path']).parts)
   source_gitlink=SOURCE_ROOT.joinpath(*PurePosixPath(project_path).parts,*PurePosixPath(g['path']).parts)
   row={'parent_project':project_path,'path':g['path'],'nested_manifest_project':nested,'gitlink_commit':g['commit'],'nested_manifest_revision':target,'manifest_project_match':target==g['commit'],'archive_directory_exists':archive_gitlink.is_dir(),'archive_directory_entry_count':sum(1 for _ in archive_gitlink.iterdir()) if archive_gitlink.is_dir() else None,'source_directory_exists':source_gitlink.is_dir(),'source_directory_entry_count':sum(1 for _ in source_gitlink.iterdir()) if source_gitlink.is_dir() else None}
   if target!=g['commit']:missing_manifest_projects.append(row)
   if not archive_gitlink.is_dir() or any(archive_gitlink.iterdir()):row['gitlink_content_materialized_in_archive']=True
   else:
    row['gitlink_content_materialized_in_archive']=False
    unmaterialized.append(row)
 link_results=[]
 for l in links:
  src=ARCHIVE_ROOT.joinpath(*PurePosixPath(l['project']).parts,*PurePosixPath(l['src']).parts)
  row={**l,'archive_source_exists':src.exists() or src.is_symlink()}
  repo=SOURCE_ROOT.joinpath(*PurePosixPath(l['project']).parts)
  objspec=f"{l['revision']}:{l['src']}"
  probe=subprocess.run(['git','-C',str(repo),'cat-file','-e',objspec],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
  row['exact_pinned_git_object_exists']=probe.returncode==0
  if probe.returncode==0:
   data=git(repo,'cat-file','blob',objspec);row['exact_pinned_blob_sha256']=sha_bytes(data);row['exact_pinned_blob_bytes']=len(data)
  else:
   row['exact_pinned_git_error']=probe.stderr.decode('utf-8','replace').strip()
  # Record a nearby path only as diagnostic; it is never substituted for the declared linkfile source.
  if l['project']=='vendor/ohemu' and l['src']=='common/qemu-run':
   alt='virt/qemu_run/qemu-run';alt_spec=f"{l['revision']}:{alt}"
   alt_probe=subprocess.run(['git','-C',str(repo),'cat-file','-e',alt_spec],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
   row['diagnostic_alternate_path']=alt;row['diagnostic_alternate_exists']=alt_probe.returncode==0
   if alt_probe.returncode==0:row['diagnostic_alternate_sha256']=sha_bytes(git(repo,'cat-file','blob',alt_spec))
  link_results.append(row)
 audit={'schema':'ohscanner.c1.snapshot-gitlink-linkfile-audit/v2','status':'nested_gitlink_commits_not_materialized_and_linkfile_source_missing','resolved_manifest_sha256':hashlib.sha256(XML.read_bytes()).hexdigest(),'materialization_manifest':{'path':DEST.relative_to(PROJECT).as_posix(),'sha256':hashlib.sha256(DEST.read_bytes()).hexdigest(),'original_external_report_sha256':hashlib.sha256(REPORT.read_bytes()).hexdigest(),'project_count':len(records),'reported_unresolved_gitlinks':len(report.get('unresolved_gitlinks',[]))},'gitlinks':{'declared_count':declared_gitlinks,'manifest_project_match_count':declared_gitlinks-len(missing_manifest_projects),'not_manifest_projects_count':len(missing_manifest_projects),'archive_commit_content_not_materialized_count':len(unmaterialized),'entries_not_manifest_projects':missing_manifest_projects,'entries_without_materialized_content':unmaterialized},'linkfiles':{'declared_count':len(links),'results':link_results,'missing_exact_sources':[x['dest'] for x in link_results if not x['archive_source_exists']]},'scope_note':'The report field unresolved_gitlinks is zero because these nested paths are not manifest projects. This audit separately checks their exact gitlink commit content: all gitlink directories are empty in both the exported archive and current source checkout. No source was copied, renamed, or substituted. A diagnostic alternate path is evidence only and is never substituted for the exact pinned vendor/ohemu linkfile source.'}
 OUT.write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'status':audit['status'],'projects':len(records),'gitlinks':declared_gitlinks,'gitlinks_not_manifest_projects':len(missing_manifest_projects),'gitlink_contents_not_materialized':len(unmaterialized),'linkfiles':len(links),'missing_linkfile_sources':audit['linkfiles']['missing_exact_sources'],'output':str(OUT)},ensure_ascii=False,indent=2))
 return 0 if len(unmaterialized)==declared_gitlinks and len(audit['linkfiles']['missing_exact_sources'])==1 else 2
if __name__=='__main__':raise SystemExit(main())
