import sys
import zipfile
from pathlib import Path

zip_path = Path(sys.argv[1])
dest = Path(sys.argv[2])
with zipfile.ZipFile(zip_path) as archive:
    names = archive.namelist()
    archive.extractall(dest)
(dest / "tests" / "__init__.py").write_text("", encoding="utf-8")
(dest / "tests" / "detectors" / "__init__.py").write_text("", encoding="utf-8")
print(f"extracted {len(names)} entries and installed package markers")