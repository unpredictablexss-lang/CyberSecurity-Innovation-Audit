from __future__ import annotations
import json, subprocess, sys
from pathlib import Path

def git(repo: Path, *args: str) -> bytes:
    p=subprocess.run(["git","-C",str(repo),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=60)
    if p.returncode: raise RuntimeError(p.stderr.decode("utf-8","replace")[:300])
    return p.stdout

def main():
    manifest=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out=[]
    for rec in manifest["records"]:
        repo=Path(rec["wsl_repo_dir"])
        for d in rec["diagnostics"]:
            if d["rule_id"] in {"ohcpp-shared-ptr-race-candidate-001","ipc.relay.descriptor-boundary"}:
                continue
            try:
                data=git(repo,"cat-file","blob",f"{rec['commit']}:{d['file']}")
                text=data.decode("utf-8","replace")
                lines=text.splitlines()
                line=int(d["line"])
                start=max(1,line-18); end=min(len(lines),line+18)
                out.append({
                    "sample_order":rec["sample_order"],"repository":rec["repository"],"commit":rec["commit"],
                    "diagnostic_id":d["diagnostic_id"],"rule_id":d["rule_id"],"file":d["file"],"line":line,
                    "symbol":d.get("symbol"),"message":d["message"],"source_sha256":d["source_sha256"],
                    "excerpt":"\n".join(f"{i}: {lines[i-1]}" for i in range(start,end+1))
                })
            except Exception as e:
                out.append({"sample_order":rec["sample_order"],"repository":rec["repository"],"diagnostic_id":d["diagnostic_id"],"error":str(e)})
    Path(sys.argv[2]).write_text(json.dumps({"schema_version":"context-extract-v1","items":out},ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("contexts",len(out))

if __name__=="__main__": main()
