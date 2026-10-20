from pathlib import Path

FILES = (
    'research/experiments/ark_runtime/c9_current_history_replay_20261019/replay.py',
    'research/experiments/ark_runtime/c9_current_history_replay_20261019/test_current_history_replay.py',
    'research/experiments/ark_runtime/c9_current_history_replay_20261019/measure.py',
    'research/experiments/ark_runtime/c9_current_history_replay_20261019/compile_check.py',
)

for relative in FILES:
    path = Path(relative)
    source = path.read_text(encoding='utf-8')
    compile(source, str(path), 'exec')
    print('compiled-in-memory', relative)
