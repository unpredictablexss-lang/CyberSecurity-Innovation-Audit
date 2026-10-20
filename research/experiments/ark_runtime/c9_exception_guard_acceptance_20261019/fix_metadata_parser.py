from pathlib import Path
path = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard/research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/write_final_metadata.py")
text = path.read_text(encoding="utf-8")
text = text.replace('f"{name}.stdout.txt"', 'f"{name}.stderr.txt"')
path.write_text(text, encoding="utf-8")
