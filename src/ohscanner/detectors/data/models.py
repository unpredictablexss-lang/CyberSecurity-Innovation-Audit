"""Explicit source/sink models; no sensitive-name heuristics or catalog registration."""
from dataclasses import dataclass

SOURCE_MODEL_VERSION = '0.1.0'  # D2 keeps D1 source/sink semantics and pinned scope.

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

SINKS = (tuple(ExposureSinkModel('AUTH_LOG'+level, 1) for level in 'FEWID') +
    tuple(ExposureSinkModel('TRANS_LOG'+level, 1) for level in 'FEWID') +
    tuple(ExposureSinkModel('COMM_LOG'+level, 1) for level in 'FEWID') +
    tuple(ExposureSinkModel(name, 3) for name in (
        'TRANS_CHECK_AND_RETURN_RET_LOGW', 'TRANS_CHECK_AND_RETURN_RET_LOGE',
        'COMM_CHECK_AND_RETURN_RET_LOGW', 'COMM_CHECK_AND_RETURN_RET_LOGE')) +
    tuple(ExposureSinkModel(name, 2) for name in (
        'TRANS_CHECK_AND_RETURN_LOGW', 'TRANS_CHECK_AND_RETURN_LOGE',
        'TRANS_CHECK_AND_RETURN_LOGD', 'COMM_CHECK_AND_RETURN_LOGW',
        'COMM_CHECK_AND_RETURN_LOGE')) +
    (ExposureSinkModel('HiLogPrint', 4), ExposureSinkModel('OH_LOG_Print', 4),
     ExposureSinkModel('HILOG_IMPL', 4)))

DEFAULT_SOURCE = SensitiveSourceModel('openharmony/communication_dsoftbus', DSOFTBUS_COMMIT)
