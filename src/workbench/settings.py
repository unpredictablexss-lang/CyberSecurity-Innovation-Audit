from dataclasses import dataclass, field
import json
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    _configured_target_roots: tuple[Path, ...] = field(repr=False)
    performance_mode: str
    max_concurrent_scans: int

    def __init__(self, data_dir, target_roots, performance_mode="balanced", max_concurrent_scans=None):
        object.__setattr__(self, "data_dir", Path(data_dir))
        object.__setattr__(self, "_configured_target_roots", tuple(Path(root) for root in target_roots))
        if performance_mode not in {"low", "balanced", "high"}:
            raise ValueError("performance_mode must be low, balanced, or high")
        defaults = {"low": 1, "balanced": 2, "high": 4}
        limit = defaults[performance_mode] if max_concurrent_scans is None else max_concurrent_scans
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= defaults[performance_mode]:
            raise ValueError("max_concurrent_scans must be within the selected mode's safe limit")
        object.__setattr__(self, "performance_mode", performance_mode)
        object.__setattr__(self, "max_concurrent_scans", limit)

    @property
    def target_roots(self):
        """Configured roots plus operator-managed roots, reloaded for each use."""
        from .source_roots import load_managed_roots, managed_root_is_current

        roots = list(self._configured_target_roots)
        roots.extend(
            Path(row["path"]) for row in load_managed_roots(self.data_dir)
            if managed_root_is_current(row)
        )
        unique = []
        seen = set()
        for root in roots:
            normalized = Path(root)
            if normalized not in seen:
                seen.add(normalized)
                unique.append(normalized)
        return tuple(unique)

    @classmethod
    def from_env(cls):
        home = Path.home()
        project_root = Path(__file__).resolve().parents[2]
        config_path = Path(os.environ.get(
            "OHSCANNER_CONFIG", str(project_root / "config" / "workbench.local.json")
        )).expanduser()
        config = {}
        if config_path.is_file():
            config = json.loads(config_path.read_text(encoding="utf-8"))
            if not isinstance(config, dict):
                raise ValueError("OHSCANNER_CONFIG must contain a JSON object")
        elif os.environ.get("OHSCANNER_CONFIG"):
            raise FileNotFoundError("OHSCANNER_CONFIG file does not exist: " + str(config_path))

        def resolve(value, setting_name):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{setting_name} must be a non-empty path string")
            path = Path(value).expanduser()
            if not path.is_absolute():
                path = config_path.resolve().parent / path
            return path.resolve()

        if "OHSCANNER_DATA" in os.environ:
            data_value = os.environ["OHSCANNER_DATA"]
        elif "data_dir" in config:
            data_value = config["data_dir"]
        else:
            data_value = str(home / "ohscanner-workbench" / "data")
        data = resolve(data_value, "OHSCANNER_DATA/data_dir")

        roots_value = os.environ.get("OHSCANNER_TARGET_ROOTS")
        if roots_value is not None:
            root_values = [value for value in roots_value.split(os.pathsep) if value]
        elif "target_roots" in config:
            root_values = config["target_roots"]
        else:
            root_values = [
                str(home / value)
                for value in (
                    "openharmony-targets",
                    "oh-audit-targets",
                    "openharmony-audit/perf-corpus",
                )
            ]
        if not isinstance(root_values, list) or not all(isinstance(value, str) for value in root_values):
            raise ValueError("OHSCANNER_CONFIG target_roots must be a list of path strings")
        configured = tuple(resolve(value, "OHSCANNER_TARGET_ROOTS/target_roots entry") for value in root_values)
        managed_cache = data / "repo-cache"
        mode = os.environ.get("OHSCANNER_PERFORMANCE_MODE", config.get("performance_mode", "balanced"))
        defaults = {"low": 1, "balanced": 2, "high": 4}
        if mode not in defaults:
            raise ValueError("performance_mode must be low, balanced, or high")
        requested = os.environ.get("OHSCANNER_MAX_CONCURRENT_SCANS", config.get("max_concurrent_scans"))
        limit = defaults[mode] if requested is None else int(requested)
        return cls(data, configured + (managed_cache,), mode, limit)

    def initialize(self):
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.data_dir / "artifacts").mkdir(exist_ok=True)
        (self.data_dir / "repo-cache").mkdir(exist_ok=True, mode=0o700)
