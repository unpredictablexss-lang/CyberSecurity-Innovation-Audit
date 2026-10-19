"""Explicit reviewed historical Source/Sink profiles, separate from default model."""
from dataclasses import dataclass
import json
from pathlib import Path
from .models import SensitiveSourceModel


@dataclass(frozen=True)
class HistoricalSourceModel(SensitiveSourceModel):
    profile: object = None


def historical_model(commit):
    """Caller must explicitly select a supported exact commit; no fallback model."""
    profiles = json.loads(Path(__file__).with_name('historical_profiles.json').read_text())['profiles']
    for p in profiles:
        if p['commit'] == commit:
            return HistoricalSourceModel(p['repository'], commit, fields=(), output_calls=(),
                parameters=(), provenance=p['source_semantics'], profile=p)
    raise ValueError('No reviewed historical model for exact commit')
