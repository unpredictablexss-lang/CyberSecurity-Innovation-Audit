"""Controlled ASan PoC for unique_ptr/raw-alias lifetime candidates."""
from __future__ import annotations

import argparse, hashlib, json, platform, subprocess, time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence, Tuple

from src.ohscanner.contracts import SourceUnit
from src.ohscanner.detectors.cpp.lifetime_detector import LifetimeOwnershipGuardDetector

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MANIFEST = Path(__file__).resolve().parent / "harnesses/cpp_lifetime_unique_ptr_alias/manifest.json"
DEFAULT_HARNESS = DEFAULT_MANIFEST.parent / "harness.cpp"
VARIANTS = ("reset_vulnerable", "null_assignment_vulnerable", "replacement_vulnerable", "move_transfer_vulnerable", "fixed_rebind", "safe_use_before_reset")
VULNERABLE = set(VARIANTS[:4])
ASAN_MARKERS = ("ERROR: AddressSanitizer:", "SUMMARY: AddressSanitizer:")


class HarnessMismatch(ValueError):
    pass


@dataclass(frozen=True)
class BuildRecord:
    variant: str
    command: Tuple[str, ...]
    exit_code: Optional[int]
    elapsed_seconds: float
    stdout: str
    stderr: str
    outcome: str


@dataclass(frozen=True)
class RunRecord:
    variant: str
    repeat: int
    command: Tuple[str, ...]
    exit_code: Optional[int]
    elapsed_seconds: float
    stdout: str
    stderr: str
    sanitizer_detected: bool
    outcome: str


@dataclass(frozen=True)
class LifetimeUafPocResult:
    package_id: str
    detector_id: str
    detector_version: str
    source_binding_status: str
    harness_sha256: str
    builds: Tuple[BuildRecord, ...]
    runs: Tuple[RunRecord, ...]
    repeats: int
    outcome: str
    detector_runs: Mapping[str, object] = field(default_factory=dict)
    environment: Mapping[str, object] = field(default_factory=dict)
    limitations: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": 1,
            "package_id": self.package_id,
            "detector": {"id": self.detector_id, "version": self.detector_version, "rule_id": "ohcpp-lifetime-unique-raw-alias-reset-001"},
            "candidate_status": "candidate/unassessed",
            "candidate_cwe": "CWE-416",
            "source_binding_status": self.source_binding_status,
            "harness_sha256": self.harness_sha256,
            "environment": dict(self.environment),
            "builds": [asdict(item) for item in self.builds],
            "runs": [asdict(item) for item in self.runs],
            "repeats": self.repeats,
            "outcome": self.outcome,
            "evidence_level": "controlled_dynamic_reproduction",
            "validated_vulnerability": 0,
            "patch_revalidation": {"status": "passed" if self.outcome == "stable_reproduced_and_patch_revalidated" else "failed_or_inconclusive", "variants": ["fixed_rebind", "safe_use_before_reset"]},
            "detector_runs": dict(self.detector_runs),
            "limitations": list(self.limitations),
        }


def load_manifest(path: Path = DEFAULT_MANIFEST) -> Dict[str, object]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def verify_harness(manifest: Mapping[str, object], harness: Path = DEFAULT_HARNESS) -> str:
    actual = _sha256_bytes(Path(harness).read_bytes())
    if actual != manifest["harness_sha256"]:
        raise HarnessMismatch(f"harness SHA-256 mismatch: expected {manifest['harness_sha256']}, read {actual}")
    return actual


def run_detector_on_source(path: str, source: str) -> Dict[str, object]:
    unit = SourceUnit(path=path, language="cpp", text=source, sha256=_sha256_text(source), parse_status="complete")
    run = LifetimeOwnershipGuardDetector().detect(None, (unit,))
    return {"detector_id": run.detector_id, "version": run.version, "status": run.status, "finding_count": len(run.findings), "findings": [{"line": f.line, "rule_id": f.rule_id, "candidate_cwe": f.candidate_cwe, "symbol": f.symbol, "source_sha256": f.source_sha256} for f in run.findings], "limitations": list(run.limitations)}


def _run_process(command: Sequence[str], cwd: Path, timeout: float, env: Optional[Dict[str, str]] = None) -> Tuple[Optional[int], float, str, str, bool]:
    started = time.perf_counter()
    try:
        process = subprocess.run(list(command), cwd=str(cwd), env=env, text=True, capture_output=True, timeout=timeout, check=False)
        return process.returncode, time.perf_counter() - started, process.stdout, process.stderr, False
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes): stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes): stderr = stderr.decode("utf-8", errors="replace")
        return None, time.perf_counter() - started, stdout, stderr, True


def _run_outcome(exit_code: Optional[int], stderr: str, timed_out: bool) -> Tuple[bool, str]:
    sanitizer = any(marker in stderr for marker in ASAN_MARKERS)
    if timed_out: return sanitizer, "timeout"
    if sanitizer: return True, "sanitizer_triggered"
    return False, "clean" if exit_code == 0 else "nonzero_exit"


def classify_runs(runs: Sequence[RunRecord], repeats: int) -> str:
    if repeats < 1 or len(runs) != repeats * len(VARIANTS):
        return "inconclusive"
    outcomes = {variant: {item.outcome for item in runs if item.variant == variant} for variant in VARIANTS}
    if any("timeout" in outcomes[variant] for variant in VARIANTS):
        return "inconclusive"
    if any(outcomes[variant] != {"clean"} for variant in ("fixed_rebind", "safe_use_before_reset")):
        return "patch_revalidation_failed"
    if any(len(items) != 1 for items in outcomes.values()):
        return "unstable"
    if any(outcomes[variant] != {"sanitizer_triggered"} for variant in VULNERABLE):
        return "not_reproduced"
    return "stable_reproduced_and_patch_revalidated"


def run_poc(*, manifest_path: Path = DEFAULT_MANIFEST, harness: Path = DEFAULT_HARNESS, output: Path, compiler: str = "clang++", repeats: int = 3, build_timeout: float = 60.0, run_timeout: float = 60.0) -> LifetimeUafPocResult:
    manifest = load_manifest(manifest_path)
    harness = Path(harness).resolve()
    harness_sha256 = verify_harness(manifest, harness)
    output = Path(output).resolve(); work = output / "work"; work.mkdir(parents=True, exist_ok=True)
    builds = []; binaries = {}
    for index, variant in enumerate(VARIANTS):
        binary = work / variant / "poc"; binary.parent.mkdir(parents=True, exist_ok=True)
        command = (compiler, "-std=c++17", "-g", "-O1", "-fno-omit-frame-pointer", "-fsanitize=address", "-no-pie", f"-DOH_LIFETIME_VARIANT={index}", str(harness), "-o", str(binary))
        exit_code, elapsed, stdout, stderr, timed_out = _run_process(command, work, build_timeout)
        builds.append(BuildRecord(variant, command, exit_code, elapsed, stdout, stderr, "build_timeout" if timed_out else "build_success" if exit_code == 0 else "build_failed"))
        binaries[variant] = binary
    runs = []
    if all(item.outcome == "build_success" for item in builds):
        env = dict(__import__("os").environ); env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0:handle_segv=1"
        setarch = __import__("shutil").which("setarch")
        prefix = (setarch, platform.machine(), "-R") if setarch else ()
        for repeat in range(1, repeats + 1):
            for variant in VARIANTS:
                command = prefix + (str(binaries[variant]),)
                exit_code, elapsed, stdout, stderr, timed_out = _run_process(command, work, run_timeout, env)
                sanitizer, outcome = _run_outcome(exit_code, stderr, timed_out)
                runs.append(RunRecord(variant, repeat, command, exit_code, elapsed, stdout, stderr, sanitizer, outcome))
    outcome = "build_failed" if any(item.outcome != "build_success" for item in builds) else classify_runs(runs, repeats)
    compiler_version = subprocess.run([compiler, "--version"], text=True, capture_output=True, check=False)
    environment = {"compiler": compiler, "compiler_version": (compiler_version.stdout or compiler_version.stderr).splitlines()[0], "sanitizers": ["address"], "platform": platform.platform(), "aslr_workaround": bool(__import__("shutil").which("setarch")), "variants": list(VARIANTS)}
    return LifetimeUafPocResult(manifest["package_id"], manifest["detector_id"], manifest["detector_version"], manifest["source_binding_status"], harness_sha256, tuple(builds), tuple(runs), repeats, outcome, dict(manifest.get("detector_expectations", {})), environment, tuple(manifest["known_limitations"]))


def write_reports(result: LifetimeUafPocResult, json_output: Path, markdown_output: Path) -> None:
    json_output.parent.mkdir(parents=True, exist_ok=True); markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = ["# unique_ptr raw-alias lifetime PoC", "", "> controlled component-level dynamic evidence；结果保持 candidate/unassessed。", "", f"- detector: `{result.detector_id}` `{result.detector_version}`", f"- harness SHA-256: `{result.harness_sha256}`", f"- outcome: **{result.outcome}**", "- `validated_vulnerability`: 0", "", "## Runtime", "", "| variant | repeat | outcome | ASan |", "|---|---:|---|---|"]
    lines.extend(f"| `{r.variant}` | {r.repeat} | {r.outcome} | {r.sanitizer_detected} |" for r in result.runs)
    lines.extend(["", "## Interpretation boundary", "", "本记录提供 self-authored controlled dynamic evidence；不证明真实产品入口、攻击者控制、CIA 影响或可利用性。候选不自动升级。", "", "## Remaining limitations", ""])
    lines.extend(f"- {item}" for item in result.limitations)
    markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST); parser.add_argument("--harness", type=Path, default=DEFAULT_HARNESS); parser.add_argument("--output", type=Path, required=True); parser.add_argument("--compiler", default="clang++"); parser.add_argument("--repeats", type=int, default=3); args = parser.parse_args()
    result = run_poc(manifest_path=args.manifest, harness=args.harness, output=args.output, compiler=args.compiler, repeats=args.repeats); write_reports(result, args.output / "poc.json", args.output / "poc.md"); print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()