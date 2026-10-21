from dataclasses import dataclass, field
import json
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    _configured_target_roots: tuple[Path, ...] = field(repr=False)
    repository_cache_roots: tuple[Path, ...] = field(repr=False)
    repository_cache_max_bytes: int
    repository_cache_min_free_bytes: int

    def __init__(self, data_dir, target_roots, repository_cache_roots=None,
                 repository_cache_max_bytes=0, repository_cache_min_free_bytes=1024 ** 3):
        object.__setattr__(self, "data_dir", Path(data_dir))
        object.__setattr__(self, "_configured_target_roots", tuple(Path(root) for root in target_roots))
        cache_roots = repository_cache_roots or (Path(data_dir) / "repo-cache",)
        object.__setattr__(self, "repository_cache_roots", tuple(Path(root) for root in cache_roots))
        object.__setattr__(self, "repository_cache_max_bytes", int(repository_cache_max_bytes))
        object.__setattr__(self, "repository_cache_min_free_bytes", int(repository_cache_min_free_bytes))

    @property
    def target_roots(self):
        """Configured roots plus operator-managed roots, reloaded for each use."""
        from .source_roots import load_managed_roots, managed_root_is_current

        roots = list(self._configured_target_roots)
        roots.extend(
            Path(row["path"]) for row in load_managed_roots(self.data_dir)
            if managed_root_is_current(row)
        )
        roots.extend(self.repository_cache_roots)
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

        def resolve_cache_root(value, setting_name):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{setting_name} must be a non-empty path string")
            path = Path(value).expanduser()
            if not path.is_absolute():
                path = config_path.resolve().parent / path
            absolute = path.absolute()
            if path.resolve(strict=False) != absolute:
                raise ValueError(f"{setting_name} cannot contain symbolic links")
            return absolute

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
        cache_policy = config.get("repository_cache", {})
        if not isinstance(cache_policy, dict):
            raise ValueError("repository_cache must be a JSON object")
        cache_root_values = os.environ.get("OHSCANNER_REPOSITORY_CACHE_ROOTS")
        if cache_root_values is not None:
            cache_roots = tuple(resolve_cache_root(value, "OHSCANNER_REPOSITORY_CACHE_ROOTS entry")
                                for value in cache_root_values.split(os.pathsep) if value)
        elif "roots" in cache_policy:
            if (not isinstance(cache_policy["roots"], list)
                    or not all(isinstance(value, str) for value in cache_policy["roots"])
                    or not cache_policy["roots"]):
                raise ValueError("repository_cache.roots must be a non-empty list of path strings")
            cache_roots = tuple(resolve_cache_root(value, "repository_cache.roots entry")
                                for value in cache_policy["roots"])
        else:
            cache_roots = (data / "repo-cache",)

        def nonnegative_int(env_name, config_name, default):
            raw = os.environ.get(env_name, cache_policy.get(config_name, default))
            try:
                value = int(raw)
            except (TypeError, ValueError):
                raise ValueError(f"{env_name}/{config_name} must be a non-negative integer") from None
            if value < 0:
                raise ValueError(f"{env_name}/{config_name} must be a non-negative integer")
            return value

        cache_max_bytes = nonnegative_int("OHSCANNER_REPOSITORY_CACHE_MAX_BYTES", "max_bytes", 0)
        cache_min_free_bytes = nonnegative_int(
            "OHSCANNER_REPOSITORY_CACHE_MIN_FREE_BYTES", "minimum_free_bytes", 1024 ** 3
        )
        return cls(data, configured, cache_roots, cache_max_bytes, cache_min_free_bytes)

    def initialize(self):
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.data_dir / "artifacts").mkdir(exist_ok=True)
        for root in self.repository_cache_roots:
            root = Path(root)
            if not root.is_absolute() or root.resolve(strict=False) != root.absolute():
                raise ValueError("repository cache roots must be absolute paths without symbolic links")
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            if root.resolve(strict=True) != root.absolute():
                raise ValueError("repository cache root changed to a symbolic link")
