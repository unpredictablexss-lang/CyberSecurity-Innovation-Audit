"""C13 experiment-only model selection for the production CLI.

The production catalog intentionally binds the C1 product snapshot. C13 needs
the reviewed historical parent/fixed bindings from the source audit. This
module changes only experiment process startup; it does not modify scanner
sources, contracts, Runner, or Catalog.
"""
from dataclasses import replace
import src.ohscanner.detectors.ark_runtime.model as _model


def _c13_historical_replay_model():
    base = _model.RuntimeTypeModel()
    historical = (
        ('2ea501258ab4155826b64f01b499b43d1911e0e2',
         'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp',
         '054451b1be4f39254d56a1683cc9d1c1b5e55018',
         '847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422'),
        ('919e4fbb011f610427e788889083fa8e28d2f951',
         'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp',
         '95f54f2875f401afe3167c62f8c1e7799782be8c',
         '8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e'),
    )
    return replace(base, target_bindings=historical, source_dependencies=())


_model.c_line_static_model = _c13_historical_replay_model
