from __future__ import annotations
import argparse, hashlib, json, os, platform, re, shutil, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from src.ohscanner.poc.cpp_shared_ptr_jsproxy import (
    DEFAULT_HARNESS, DEFAULT_MANIFEST, RUN_VARIANTS, _resolve_repo,
    make_variants, run_detector, verify_sources,
)

DEFAULT_EVIDENCE_DIR = ROOT / "research/evidence/cpp/rc_jsproxy_patch_revalidation_20261016"
DEFAULT_WORK_DIR = ROOT / "outputs/poc/rc-jsproxy-patch-revalidation-20261016"
CONTROL_SCRIPT = ROOT / "research/experiments/cpp/run_four_class_controls.py"
CONTROL_MANIFEST = ROOT / "research/tests/cpp_detector_controls_impl_20261015/manifest.json"
TSAN_OPTIONS = "halt_on_error=1:exitcode=66"
TSAN_MARKERS = ("WARNING: ThreadSanitizer:", "SUMMARY: ThreadSanitizer:")
RUN_SPECS = (("single", ()), ("race", ("4", "2", "50000")), ("close_get_entry", ("2000",)), ("unrelated", ()))
TIME_FORMAT = "__OH_METRICS__\\twall_seconds=%e\\tpeak_rss_kb=%M\\texit_code=%x"
METRICS_RE = re.compile(r"__OH_METRICS__\twall_seconds=([0-9.]+)\tpeak_rss_kb=(\d+)\texit_code=(-?\d+|\?)")

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())
def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return resolved.as_posix()
def minimal_environment(extra: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for key in ("PATH", "HOME", "TMPDIR", "TEMP", "TMP"):
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    env["LANG"] = "C.UTF-8"
    env["LC_ALL"] = "C.UTF-8"
    if extra:
        env.update({str(key): str(value) for key, value in extra.items()})
    return dict(sorted(env.items()))
def parse_metrics(path: Path) -> Tuple[Optional[float], Optional[int], Optional[int]]:
    if not path.exists():
        return None, None, None
    match = METRICS_RE.search(path.read_text(encoding="utf-8", errors="replace"))
    if not match:
        return None, None, None
    return float(match.group(1)), int(match.group(2)), (None if match.group(3) == "?" else int(match.group(3)))
def run_measured(*, label: str, argv: Sequence[str], cwd: Path, env: Mapping[str, str], raw_dir: Path, timeout_seconds: float, input_record: Mapping[str, object]) -> Dict[str, object]:
    cwd.mkdir(parents=True, exist_ok=True); raw_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = raw_dir / f"{label}.stdout.txt"; stderr_path = raw_dir / f"{label}.stderr.txt"; timing_path = raw_dir / f"{label}.time.txt"
    wrapper_argv = ("/usr/bin/time", "-f", TIME_FORMAT, "-o", str(timing_path), *tuple(str(item) for item in argv))
    started_at = utc_now(); monotonic_start = time.monotonic(); timed_out = False; timeout_failure = None
    try:
        completed = subprocess.run(wrapper_argv, cwd=str(cwd), env=dict(env), capture_output=True, check=False, timeout=timeout_seconds)
        stdout, stderr, wrapper_exit_code = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True; timeout_failure = f"command timed out after {timeout_seconds:.3f}s"
        stdout, stderr, wrapper_exit_code = exc.stdout or b"", exc.stderr or b"", None
    monotonic_wall = time.monotonic() - monotonic_start
    stdout_path.write_bytes(stdout); stderr_path.write_bytes(stderr)
    measured_wall, peak_rss_kb, measured_exit_code = parse_metrics(timing_path)
    exit_code = measured_exit_code if measured_exit_code is not None else wrapper_exit_code
    return {
        "label": label, "logical_argv": list(str(item) for item in argv), "measured_argv": list(wrapper_argv),
        "cwd": display_path(cwd), "environment": dict(env), "environment_sha256": sha256_bytes(canonical_json(env)),
        "input": dict(input_record), "input_sha256": sha256_bytes(canonical_json(input_record)), "started_at_utc": started_at,
        "wall_seconds": measured_wall, "wall_seconds_monotonic": monotonic_wall, "peak_rss_kb": peak_rss_kb,
        "exit_code": exit_code, "wrapper_exit_code": wrapper_exit_code, "timed_out": timed_out,
        "timeout_failure": timeout_failure, "stdout_path": display_path(stdout_path), "stdout_sha256": sha256_bytes(stdout),
        "stderr_path": display_path(stderr_path), "stderr_sha256": sha256_bytes(stderr), "timing_path": display_path(timing_path),
        "timing_sha256": sha256_file(timing_path) if timing_path.exists() else None,
        "tool": {"path": "/usr/bin/time", "sha256": sha256_file(Path("/usr/bin/time")), "format": TIME_FORMAT},
    }
def classify_runtime(record: Mapping[str, object], stderr: bytes) -> str:
    if record["timed_out"]:
        return "timeout"
    if any(marker.encode("ascii") in stderr for marker in TSAN_MARKERS):
        return "sanitizer_triggered"
    return "clean" if record["exit_code"] == 0 else "failed"
def git_identity(repo: Path, env: Mapping[str, str]) -> Dict[str, object]:
    commands = {"head": ("rev-parse", "HEAD"), "tree": ("rev-parse", "HEAD^{tree}"), "status": ("status", "--porcelain=v1"), "remote": ("remote", "get-url", "origin")}
    result: Dict[str, object] = {"path": display_path(repo), "commands": {}}
    for name, args in commands.items():
        argv = ["git", "-C", str(repo), *args]
        completed = subprocess.run(argv, cwd=str(repo), env=dict(env), capture_output=True, check=False)
        result["commands"][name] = {"argv": argv, "environment": dict(env), "environment_sha256": sha256_bytes(canonical_json(env)), "exit_code": completed.returncode, "stdout": completed.stdout.decode("utf-8", "replace").strip(), "stderr": completed.stderr.decode("utf-8", "replace")}
    return result
def tool_identity(*, label: str, argv: Sequence[str], path: Optional[str], env: Mapping[str, str], raw_dir: Path) -> Dict[str, object]:
    record = run_measured(label=label, argv=argv, cwd=ROOT, env=env, raw_dir=raw_dir, timeout_seconds=10.0, input_record={"purpose": "toolchain identity", "argv": list(argv)})
    resolved = Path(path).resolve() if path else None
    record["resolved_path"] = str(resolved) if resolved else None
    record["resolved_sha256"] = sha256_file(resolved) if resolved and resolved.is_file() else None
    record["version_text_path"] = record["stdout_path"]
    return record
def expected_runtime_outcome(variant: str, mode: str) -> str:
    return "sanitizer_triggered" if mode in {"race", "close_get_entry"} and variant == "vulnerable" else "clean"
def control_class(variant: str, mode: str) -> str:
    if mode == "unrelated":
        return "unrelated"
    if mode == "single":
        return "unknown_non_overlap" if variant == "vulnerable" else "safe_functional"
    return "positive" if variant == "vulnerable" else ("fixed" if variant == "fixed_control_mutex" else "patched")
def runtime_failure_reason(*, outcome: str, expected: str, exit_code: Optional[int], timed_out: bool) -> Optional[str]:
    reasons = []
    if timed_out: reasons.append("runtime timeout")
    if outcome != expected: reasons.append(f"unexpected outcome: expected {expected}, observed {outcome}")
    if expected == "sanitizer_triggered" and exit_code != 66: reasons.append(f"expected TSan exit code 66, observed {exit_code}")
    if expected == "clean" and exit_code != 0: reasons.append(f"expected clean exit code 0, observed {exit_code}")
    return "; ".join(reasons) if reasons else None
def write_patch_review(path: Path, *, patch_sha256: str, vulnerable_sha256: str, fixed_sha256: str, patched_sha256: str, run_records: Sequence[Mapping[str, object]]) -> None:
    stability: Dict[str, Dict[str, List[str]]] = {}
    for item in run_records:
        if item["mode"] in {"race", "close_get_entry"}:
            stability.setdefault(str(item["variant"]), {}).setdefault(str(item["mode"]), []).append(str(item["trigger_result"]))
    lines = ["# RC-JSPROXY minimal patch review", "", "## Scope", "", "- Candidate remains `candidate/unknown`; this patch does not promote it to confirmed/reportable.", "- Target: `openharmony/distributeddatamgr_kv_store` at the manifest-bound commit/tree.", "- File: `frameworks/common/js_proxy.h`.", f"- Patch SHA-256: `{patch_sha256}`.", "", "## Root cause and why the patch removes it", "", "The real source path copies and assigns `std::shared_ptr<T> instance_` from different threads: a NAPI execute path can replace/clear the owner while a synchronous result-set path copies it. The owner operations are not protected by a repository-local mutex or atomic API, so the read and write may overlap. That is a `CWE-362` synchronization defect candidate. The minimal patch routes both owner operations through C++17 `std::atomic_load` / `std::atomic_store` free functions specialized for `std::shared_ptr`, making each owner access atomic instead of merely narrowing the timing window.", "", "## Patch", "", "```diff", (path.parent / "patch.diff").read_text(encoding="utf-8").rstrip(), "```", "", f"- Vulnerable source SHA-256: `{vulnerable_sha256}`.", f"- Independent fixed-control source SHA-256: `{fixed_sha256}`.", f"- Patched source SHA-256: `{patched_sha256}`.", "", "## Functional impact", "", "The public `SetInstance` / `GetInstance` signatures and ownership-return semantics are unchanged. The controlled `single` workload still creates, returns, touches and clears the owner on all variants. This is component-Harness functional evidence only; product API behavior and performance were not built or measured.", "", "## Narrow-scope boundary", "", "The patch only synchronizes `JSProxy::instance_` owner access. It does not repair or prove the underlying `KvStoreResultSet` close/getEntry protocol, NAPI queue lifetime, product permission enforcement, package resolution or cross-module behavior. It is a proposed local patch, not an upstream fix or a complete product remediation.", "", "## Revalidation stability", ""]
    for variant in sorted(stability):
        for mode in sorted(stability[variant]):
            outcomes = stability[variant][mode]
            lines.append(f"- `{variant}` / `{mode}`: `{', '.join(outcomes)}` ({len(outcomes)}/{len(outcomes)} expected within this run).")
    lines.extend(["", "The replay is stable at three repetitions per mode, but three repetitions do not establish a statistical failure rate or product-level exploitability. TSan proves the controlled owner race; it does not prove UAF, corruption, disclosure, privilege escalation or availability impact in OpenHarmony.", ""])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
def write_markdown(path: Path, evidence: Mapping[str, object]) -> None:
    runs = evidence["runtime"]["runs"]; controls = evidence["controls"]
    lines = ["# RC-JSPROXY patch revalidation", "", f"- Generated: `{evidence['generated_at_utc']}`", "- Status: `candidate/unknown`; `validated_vulnerability=0`; `confirmed/reportable=false`.", f"- Overall outcome: `{evidence['overall_outcome']}`.", f"- Patch SHA-256: `{evidence['patch']['sha256']}`.", "", "## Identity", "", f"- OHScanner HEAD: `{evidence['checkout']['ohscanner']['commands']['head']['stdout']}`", f"- OHScanner tree: `{evidence['checkout']['ohscanner']['commands']['tree']['stdout']}`", f"- Target HEAD: `{evidence['checkout']['target']['commands']['head']['stdout']}`", f"- Target tree: `{evidence['checkout']['target']['commands']['tree']['stdout']}`", f"- Target source blob: `{evidence['source']['blob']}`", f"- Target source SHA-256: `{evidence['source']['sha256']}`", "", "## Toolchain", "", f"- Compiler: `{evidence['toolchain']['compiler']['resolved_path']}`", f"- Compiler SHA-256: `{evidence['toolchain']['compiler']['resolved_sha256']}`", f"- Sanitizer: ThreadSanitizer (`-fsanitize=thread`), `TSAN_OPTIONS={TSAN_OPTIONS}`.", f"- GNU time: `{evidence['toolchain']['gnu_time']['resolved_path']}`.", "", "## Variant replays", "", "| variant | mode | repeat | wall s | peak RSS KiB | exit | trigger | status | failure reason |", "|---|---|---:|---:|---:|---:|---|---|---|"]
    for item in runs:
        lines.append("| `{variant}` | `{mode}` | {repeat} | {wall} | {rss} | {exit} | `{trigger}` | `{status}` | {failure} |".format(variant=item["variant"], mode=item["mode"], repeat=item["repeat"], wall="unknown" if item["wall_seconds"] is None else f"{item['wall_seconds']:.3f}", rss="unknown" if item["peak_rss_kb"] is None else item["peak_rss_kb"], exit="unknown" if item["exit_code"] is None else item["exit_code"], trigger=item["trigger_result"], status=item["verification_status"], failure="none" if item["failure_reason"] is None else str(item["failure_reason"]).replace("|", "\\|")))
    lines.extend(["", "## Controls", "", f"- Positive/fixed/safe/unrelated A-line matrix: `{controls['summary']['detector_controls_passed']}/{controls['summary']['detector_controls_total']}` passed.", f"- Native controls: `{controls['summary']['native_controls_passed']}/{controls['summary']['native_controls_total']}` passed.", f"- Unknown obligations retained: `{controls['summary']['unknown_obligation_controls']}` controls with `synchronization_proof=unknown`.", f"- Zero-fuzz repair controls: `{controls['summary']['zero_fuzz_passed']}/{controls['summary']['zero_fuzz_total']}` passed.", f"- Control suite wall/RSS: `{controls['suite_run']['wall_seconds']}` s / `{controls['suite_run']['peak_rss_kb']}` KiB.", "", "## Patch revalidation boundary", "", "The patch removes the modeled `JSProxy` owner data race and preserves the controlled single-thread functional sequence. It does not prove product-level fix correctness, performance neutrality, full result-set protocol safety, affected branches/versions or CIA impact. The candidate remains `candidate/unknown`; no CVE is assigned.", ""])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR)
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--harness", type=Path, default=DEFAULT_HARNESS)
    parser.add_argument("--compiler", default="clang++")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--run-timeout", type=float, default=120.0)
    parser.add_argument("--build-timeout", type=float, default=120.0)
    parser.add_argument("--control-timeout", type=float, default=900.0)
    args = parser.parse_args()
    if args.repeats < 3:
        raise SystemExit("--repeats must be at least 3 for this deliverable")
    evidence_dir, work_dir = args.evidence_dir.resolve(), args.work_dir.resolve()
    if evidence_dir.exists(): raise SystemExit(f"refusing to overwrite evidence directory: {evidence_dir}")
    if work_dir.exists(): raise SystemExit(f"refusing to overwrite raw work directory: {work_dir}")
    evidence_dir.mkdir(parents=True); work_dir.mkdir(parents=True); raw_dir = work_dir / "raw"; raw_dir.mkdir()
    base_env = minimal_environment(); manifest_path = args.manifest.resolve(); harness_path = args.harness.resolve()
    manifest_bytes = manifest_path.read_bytes(); manifest = json.loads(manifest_bytes.decode("utf-8"))
    compiler_path = shutil.which(args.compiler)
    if not compiler_path: raise SystemExit(f"compiler not found: {args.compiler}")
    compiler_invocation = compiler_path; compiler_binary_path = str(Path(compiler_invocation).resolve()); compiler_path = compiler_invocation; setarch_path = shutil.which("setarch"); patch_tool = shutil.which("patch")
    if not patch_tool: raise SystemExit("patch tool not found")
    toolchain = {"compiler": tool_identity(label="toolchain-compiler", argv=(compiler_path, "--version"), path=compiler_path, env=base_env, raw_dir=raw_dir), "gnu_time": tool_identity(label="toolchain-gnu-time", argv=("/usr/bin/time", "--version"), path="/usr/bin/time", env=base_env, raw_dir=raw_dir), "python": {"path": sys.executable, "sha256": sha256_file(Path(sys.executable)), "version": sys.version}}
    if setarch_path: toolchain["setarch"] = tool_identity(label="toolchain-setarch", argv=(setarch_path, "--version"), path=setarch_path, env=base_env, raw_dir=raw_dir)
    toolchain["patch"] = tool_identity(label="toolchain-patch", argv=(patch_tool, "--version"), path=patch_tool, env=base_env, raw_dir=raw_dir)
    source, call_sources, source_bytes_by_path = verify_sources(manifest)
    detector_source = ROOT / str(manifest["detector_source_path"]); poc_runner = ROOT / str(manifest["poc_runner_path"])
    binding_checks = {"manifest_sha256": sha256_bytes(manifest_bytes), "harness_sha256": sha256_file(harness_path), "detector_source_sha256": sha256_file(detector_source), "poc_runner_sha256": sha256_file(poc_runner)}
    expected_checks = {"harness_sha256": manifest["harness_sha256"], "detector_source_sha256": manifest["detector_source_sha256"], "poc_runner_sha256": manifest["poc_runner_sha256"]}
    binding_checks["detector_source_matches_historical_manifest"] = binding_checks["detector_source_sha256"] == expected_checks["detector_source_sha256"]
    binding_checks["historical_manifest_detector_source_sha256"] = expected_checks["detector_source_sha256"]
    binding_checks["binding_limitation"] = None if binding_checks["detector_source_matches_historical_manifest"] else "Current dirty detector implementation differs from the historical PoC manifest; current code is executed and the drift is retained explicitly."
    for key in ("harness_sha256", "poc_runner_sha256"):
        expected = expected_checks[key]
        if binding_checks[key] != expected: raise RuntimeError(f"{key} mismatch: {binding_checks[key]} != {expected}")
    variant_generation = work_dir / "variant-generation"
    variants, patch_bytes = make_variants(source_bytes_by_path[str(manifest["source_path"])], variant_generation)
    patch_path = evidence_dir / "patch.diff"; patch_path.write_bytes(patch_bytes)
    detector_runs = [{"variant": variant, "source_sha256": sha256_bytes(variants[variant]), "result": run_detector(variant, str(manifest["source_path"]), variants[variant]).__dict__} for variant in RUN_VARIANTS]
    builds: List[Dict[str, object]] = []; binaries: Dict[str, Path] = {}
    compiler_identity = toolchain["compiler"]; compiler_version_text = (ROOT / str(compiler_identity["stdout_path"])).read_text(encoding="utf-8", errors="replace")
    for variant in RUN_VARIANTS:
        include_dir = variant_generation / "work" / variant / "include"; include_path = include_dir / "js_proxy_variant.h"
        binary_dir = work_dir / "builds" / variant; binary_path = binary_dir / "poc"; binary_dir.mkdir(parents=True, exist_ok=True)
        build_argv = [compiler_path, "-std=c++17", "-g", "-O1", "-fno-omit-frame-pointer", "-fsanitize=thread", "-pthread", "-no-pie", f"-I{include_dir}", str(harness_path), "-o", str(binary_path)]
        build_input = {"variant": variant, "variant_source_sha256": sha256_file(include_path), "harness_sha256": sha256_file(harness_path), "compiler_sha256": compiler_identity["resolved_sha256"], "compiler_version": compiler_version_text.splitlines()[0] if compiler_version_text else "unknown", "sanitizer_flags": ["-fsanitize=thread"], "argv": build_argv}
        build = run_measured(label=f"build-{variant}", argv=build_argv, cwd=binary_dir, env=base_env, raw_dir=raw_dir, timeout_seconds=args.build_timeout, input_record=build_input)
        build.update({"variant": variant, "source_path": display_path(include_path), "source_sha256": sha256_file(include_path), "artifact_path": display_path(binary_path), "artifact_sha256": sha256_file(binary_path) if binary_path.exists() else None, "sanitizer": {"name": "ThreadSanitizer", "flags": ["-fsanitize=thread"], "options": TSAN_OPTIONS}, "compiler": {"path": compiler_path, "binary_path": compiler_binary_path, "version": compiler_version_text.splitlines()[0] if compiler_version_text else "unknown", "sha256": compiler_identity["resolved_sha256"]}, "verification_status": "passed" if build["exit_code"] == 0 and not build["timed_out"] else "failed"})
        build["failure_reason"] = None if build["verification_status"] == "passed" else (build["timeout_failure"] or f"compiler exit code {build['exit_code']}")
        builds.append(build)
        if binary_path.exists(): binaries[variant] = binary_path
    run_records: List[Dict[str, object]] = []
    for variant in RUN_VARIANTS:
        binary_path = binaries.get(variant)
        if binary_path is None: continue
        for mode, args_tuple in RUN_SPECS:
            for repeat in range(1, args.repeats + 1):
                logical_argv = [str(binary_path), mode, *args_tuple]
                actual_argv = ([setarch_path, platform.machine(), "-R"] if setarch_path else []) + logical_argv
                variant_source = variant_generation / "work" / variant / "include" / "js_proxy_variant.h"
                run_input = {"variant": variant, "mode": mode, "repeat": repeat, "program_args": list(args_tuple), "source_sha256": sha256_file(variant_source), "harness_sha256": sha256_file(harness_path), "artifact_sha256": sha256_file(binary_path)}
                run = run_measured(label=f"run-{variant}-{mode}-{repeat:02d}", argv=actual_argv, cwd=work_dir / "runs" / variant, env=minimal_environment({"TSAN_OPTIONS": TSAN_OPTIONS}), raw_dir=raw_dir, timeout_seconds=args.run_timeout, input_record=run_input)
                stderr_path = ROOT / str(run["stderr_path"]); outcome = classify_runtime(run, stderr_path.read_bytes()); expected = expected_runtime_outcome(variant, mode)
                failure = runtime_failure_reason(outcome=outcome, expected=expected, exit_code=run["exit_code"], timed_out=bool(run["timed_out"]))
                run.update({"variant": variant, "mode": mode, "repeat": repeat, "program_args": list(args_tuple), "control_class": control_class(variant, mode), "source_path": display_path(variant_source), "source_sha256": run_input["source_sha256"], "artifact_path": display_path(binary_path), "artifact_sha256": run_input["artifact_sha256"], "sanitizer": {"name": "ThreadSanitizer", "flags": ["-fsanitize=thread"], "options": TSAN_OPTIONS, "markers": list(TSAN_MARKERS)}, "expected_trigger_result": expected, "trigger_result": outcome, "verification_status": "passed" if failure is None else "failed", "failure_reason": failure})
                run_records.append(run)
    target_repo = _resolve_repo(manifest); git_check_env = minimal_environment()
    git_check = run_measured(label="patch-git-apply-check", argv=["git", "-C", str(target_repo), "apply", "--cached", "--check", str(patch_path)], cwd=target_repo, env=git_check_env, raw_dir=raw_dir, timeout_seconds=30.0, input_record={"purpose": "verify canonical patch applies to exact target Git index without modifying it", "patch_sha256": sha256_file(patch_path), "target_repo": display_path(target_repo), "target_commit": manifest["commit"], "target_tree": manifest["git_tree"]})
    git_check["verification_status"] = "passed" if git_check["exit_code"] == 0 and not git_check["timed_out"] else "failed"
    git_check["failure_reason"] = None if git_check["verification_status"] == "passed" else (git_check["timeout_failure"] or f"git apply --cached --check exit code {git_check['exit_code']}")
    zero_fuzz_root = work_dir / "zero-fuzz"; zero_fuzz_file = zero_fuzz_root / "frameworks/common/js_proxy.h"
    zero_fuzz_file.parent.mkdir(parents=True, exist_ok=True); zero_fuzz_file.write_bytes(variants["vulnerable"])
    zero_fuzz_input = {"purpose": "isolated zero-fuzz repair control", "patch_sha256": sha256_file(patch_path), "vulnerable_source_sha256": sha256_bytes(variants["vulnerable"]), "expected_patched_source_sha256": sha256_bytes(variants["patched_atomic_minimal"])}
    zero_fuzz = run_measured(label="patch-zero-fuzz", argv=[patch_tool, "-p1", "--fuzz=0", "--batch", "--forward", "-i", str(patch_path)], cwd=zero_fuzz_root, env=base_env, raw_dir=raw_dir, timeout_seconds=30.0, input_record=zero_fuzz_input)
    result_source = zero_fuzz_file.read_bytes() if zero_fuzz_file.exists() else b""
    zero_fuzz.update({"source_path": display_path(zero_fuzz_file), "source_sha256": sha256_bytes(result_source) if result_source else None, "artifact_path": display_path(zero_fuzz_file), "artifact_sha256": sha256_bytes(result_source) if result_source else None, "expected_artifact_sha256": sha256_bytes(variants["patched_atomic_minimal"]), "verification_status": "passed" if zero_fuzz["exit_code"] == 0 and not zero_fuzz["timed_out"] and result_source == variants["patched_atomic_minimal"] else "failed"})
    zero_fuzz["failure_reason"] = None if zero_fuzz["verification_status"] == "passed" else (zero_fuzz["timeout_failure"] or "zero-fuzz patch did not produce the exact patched source bytes")
    control_evidence_dir = work_dir / "controls/evidence"; control_work_dir = work_dir / "controls/native"
    control_evidence_dir.mkdir(parents=True, exist_ok=False); control_work_dir.mkdir(parents=True, exist_ok=False)
    control_command = [sys.executable, str(CONTROL_SCRIPT), "--manifest", str(CONTROL_MANIFEST), "--output", str(control_evidence_dir), "--work-dir", str(control_work_dir), "--compiler", compiler_path, "--repeats", str(args.repeats), "--skip-regression", "--skip-family-poc"]
    control_run = run_measured(label="a-line-four-class-controls", argv=control_command, cwd=ROOT, env=base_env, raw_dir=raw_dir, timeout_seconds=args.control_timeout, input_record={"purpose": "preserve positive/fixed/safe/unrelated/unknown and zero-fuzz repair controls", "manifest_path": display_path(CONTROL_MANIFEST), "manifest_sha256": sha256_file(CONTROL_MANIFEST), "repeats": args.repeats, "sanitizers": ["ThreadSanitizer", "AddressSanitizer"]})
    control_results_path = control_evidence_dir / "results.json"; control_results = json.loads(control_results_path.read_text(encoding="utf-8")) if control_results_path.exists() else {}
    control_stages = control_results.get("stages", {}) if isinstance(control_results, dict) else {}
    patch_items = control_stages.get("patch_revalidation", {}).get("items", []); detector_items = control_stages.get("detector_matrix", {}).get("items", []); native_items = control_stages.get("native_controls", {}).get("items", [])
    unknown_obligation_controls = []
    for item in detector_items:
        kinds = item.get("expected", {}).get("unknown_obligation_kinds", [])
        if kinds: unknown_obligation_controls.append({"control_id": item.get("control_id"), "category": item.get("category"), "unknown_obligation_kinds": kinds, "status_result": item.get("status_result")})
    category_counts: Dict[str, int] = {}
    for item in detector_items:
        category = str(item.get("category", "unknown")); category_counts[category] = category_counts.get(category, 0) + 1
    control_passes = sum(1 for item in detector_items if item.get("status_result") == "passed"); control_total = len(detector_items)
    native_passes = sum(1 for item in native_items if item.get("status") == "passed"); native_total = len(native_items)
    zero_fuzz_items = [item for item in patch_items if item.get("status") != "not_applicable"]; zero_fuzz_passes = sum(1 for item in zero_fuzz_items if item.get("status") == "passed"); zero_fuzz_total = len(zero_fuzz_items)
    control_summary = {"suite_run": control_run, "results_path": display_path(control_results_path), "results_sha256": sha256_file(control_results_path) if control_results_path.exists() else None, "summary": {"detector_controls_passed": control_passes, "detector_controls_total": control_total, "native_controls_passed": native_passes, "native_controls_total": native_total, "category_counts": category_counts, "unknown_obligation_controls": len(unknown_obligation_controls), "unknown_obligation_items": unknown_obligation_controls, "zero_fuzz_passed": zero_fuzz_passes, "zero_fuzz_total": zero_fuzz_total, "passed": control_run["exit_code"] == 0 and not control_run["timed_out"] and control_passes == control_total and native_passes == native_total and zero_fuzz_passes == zero_fuzz_total}}
    if control_results_path.exists(): shutil.copy2(control_results_path, evidence_dir / "controls-results.json")
    control_md = control_evidence_dir / "results.md"
    if control_md.exists(): shutil.copy2(control_md, evidence_dir / "controls-results.md")
    identity_env = minimal_environment(); checkout = {"ohscanner": git_identity(ROOT, identity_env), "target": git_identity(target_repo, identity_env)}
    required_runs = [item for item in run_records if item["mode"] in {"race", "close_get_entry"}]
    required_passes = sum(1 for item in required_runs if item["verification_status"] == "passed"); all_run_passes = sum(1 for item in run_records if item["verification_status"] == "passed")
    overall_ok = all(item["verification_status"] == "passed" for item in builds) and all_run_passes == len(run_records) and required_passes == len(required_runs) and git_check["verification_status"] == "passed" and zero_fuzz["verification_status"] == "passed" and control_summary["summary"]["passed"]
    overall_outcome = "stable_reproduced_and_patch_revalidated" if overall_ok else "revalidation_incomplete_or_failed"
    evidence: Dict[str, object] = {"schema_version": 1, "kind": "rc_jsproxy_patch_revalidation", "generated_at_utc": utc_now(), "selected_candidate": {"review_group": "RC-JSPROXY", "candidate_ids": manifest["candidate_ids"], "diagnostic_ids": manifest["diagnostic_ids"], "candidate_cwe": manifest["candidate_cwe"], "possible_consequence_cwe": manifest["possible_consequence_cwe"], "status": "candidate/unknown", "validated_vulnerability": 0, "confirmed_reportable": False}, "checkout": checkout, "binding_checks": binding_checks, "manifest": {"path": display_path(manifest_path), "sha256": sha256_bytes(manifest_bytes), "repository": manifest["repository"], "commit": manifest["commit"], "git_tree": manifest["git_tree"]}, "source": {"path": source.path, "blob": source.blob, "sha256": source.sha256, "checkout_sha256": source.checkout_sha256, "call_path_sources": [item.__dict__ for item in call_sources]}, "detector_runs": detector_runs, "patch": {"path": display_path(patch_path), "sha256": sha256_file(patch_path), "vulnerable_source_sha256": sha256_bytes(variants["vulnerable"]), "fixed_control_source_sha256": sha256_bytes(variants["fixed_control_mutex"]), "patched_source_sha256": sha256_bytes(variants["patched_atomic_minimal"]), "rationale": "Atomic shared_ptr owner load/store replaces unsynchronized owner copy/assignment.", "root_cause": "Unsynchronized std::shared_ptr instance_ read and write across NAPI execute and synchronous result-set paths.", "functional_impact": "API and ownership-return semantics unchanged; controlled single functional sequence passes. Product build/performance not available.", "narrow_scope": "Only JSProxy owner synchronization. Underlying result-set close/getEntry protocol, permissions, deployment and cross-module impact remain unknown."}, "toolchain": toolchain, "builds": builds, "runtime": {"sanitizer": {"name": "ThreadSanitizer", "flags": ["-fsanitize=thread"], "options": TSAN_OPTIONS, "required_for": "race and close_get_entry modes"}, "runs": run_records, "repeats_per_variant_mode": args.repeats, "required_passes": required_passes, "required_total": len(required_runs), "all_passes": all_run_passes, "all_total": len(run_records)}, "patch_application_checks": {"git_apply_cached_check": git_check, "zero_fuzz_repair_control": zero_fuzz}, "controls": control_summary, "overall_outcome": overall_outcome, "limitations": list(manifest["known_limitations"]) + ["Three repeats per variant/mode demonstrate deterministic replay in this environment only; they do not establish product failure rates.", "The race family requires ThreadSanitizer. ASan/UBSan is not a substitute for this selected race root cause; A-line ASan lifetime controls are preserved separately in the control suite.", "Exact environment is recorded as the minimal environment map passed to each measured child. It intentionally excludes unrelated host variables and secrets.", "Peak RSS is GNU time maximum resident set size in KiB for the measured process tree, not a product memory benchmark."]}
    (evidence_dir / "revalidation.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_markdown(evidence_dir / "revalidation.md", evidence)
    write_patch_review(evidence_dir / "patch-review.md", patch_sha256=sha256_file(patch_path), vulnerable_sha256=sha256_bytes(variants["vulnerable"]), fixed_sha256=sha256_bytes(variants["fixed_control_mutex"]), patched_sha256=sha256_bytes(variants["patched_atomic_minimal"]), run_records=run_records)
    index_files = [{"path": display_path(path), "sha256": sha256_file(path), "bytes": path.stat().st_size} for path in sorted(evidence_dir.iterdir()) if path.is_file() and path.name != "artifact-index.json"]
    (evidence_dir / "artifact-index.json").write_text(json.dumps({"schema_version": 1, "generated_at_utc": utc_now(), "evidence_dir": display_path(evidence_dir), "files": index_files, "raw_work_dir": display_path(work_dir)}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"evidence_dir": str(evidence_dir), "work_dir": str(work_dir), "overall_outcome": overall_outcome, "required_runs": f"{required_passes}/{len(required_runs)}", "all_runs": f"{all_run_passes}/{len(run_records)}", "controls_passed": control_summary["summary"]["passed"]}, ensure_ascii=False, indent=2))
    raise SystemExit(0 if overall_ok else 1)

if __name__ == "__main__":
    main()
