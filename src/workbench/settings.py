from dataclasses import dataclass
import json
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    target_roots: tuple[Path, ...]

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
        return cls(data, configured + (managed_cache,))

    def initialize(self):
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.data_dir / "artifacts").mkdir(exist_ok=True)
        (self.data_dir / "repo-cache").mkdir(exist_ok=True, mode=0o700)
