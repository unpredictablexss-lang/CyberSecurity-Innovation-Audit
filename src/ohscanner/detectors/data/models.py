"""Explicit source/sink models; no sensitive-name heuristics or catalog registration."""
from dataclasses import dataclass

DSOFTBUS_COMMIT = '0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132'

@dataclass(frozen=True)
class SensitiveSourceModel:
    repository: str
    commit: str
    # Exact record type -> sensitive material field, never len/index/iv.
    fields: tuple = (('SessionKey', 'value'), ('AesGcmCipherKey', 'key'),
                     ('AesGcm128CipherKey', 'key'), ('AesCtrCipherKey', 'key'))
    output_calls: tuple = (('SoftBusGenerateSessionKey', 0),)
    # File/function/parameter-index, bound to reviewed callback semantics.
    parameters: tuple = (('core/authentication/src/auth_hichain.c', 'OnSessionKeyReturned', 1),)
    provenance: str = 'Reviewed pinned dsoftbus key declarations; research model, not product policy'

@dataclass(frozen=True)
class ExposureSinkModel:
    name: str
    format_index: int
    default_private: bool = True

SINKS = tuple(ExposureSinkModel('AUTH_LOG'+level, 1) for level in 'FEWID') + (
    ExposureSinkModel('HiLogPrint', 4), ExposureSinkModel('OH_LOG_Print', 4),
    ExposureSinkModel('HILOG_IMPL', 4),
)

DEFAULT_SOURCE = SensitiveSourceModel('openharmony/communication_dsoftbus', DSOFTBUS_COMMIT)
