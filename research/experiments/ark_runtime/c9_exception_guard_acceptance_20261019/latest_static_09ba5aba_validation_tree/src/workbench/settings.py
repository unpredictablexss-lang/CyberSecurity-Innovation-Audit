from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    target_roots: tuple[Path, ...]

    @classmethod
    def from_env(cls):
        home = Path.home()
        roots = os.environ.get(
            "OHSCANNER_TARGET_ROOTS",
            os.pathsep.join(
                str(home / x)
                for x in (
                    "openharmony-targets",
                    "oh-audit-targets",
                    "openharmony-audit/perf-corpus",
                )
            ),
        )
        data = Path(os.environ.get("OHSCANNER_DATA", str(home / "ohscanner-workbench/data"))).resolve()
        configured = tuple(Path(p).expanduser().resolve() for p in roots.split(os.pathsep) if p)
        managed_cache = data / "repo-cache"
        return cls(data, configured + (managed_cache,))

    def initialize(self):
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.data_dir / "artifacts").mkdir(exist_ok=True)
        (self.data_dir / "repo-cache").mkdir(exist_ok=True, mode=0o700)
