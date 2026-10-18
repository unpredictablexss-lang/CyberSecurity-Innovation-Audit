"""Explicit source/sink models; no sensitive-name heuristics or catalog registration."""
from dataclasses import dataclass

SOURCE_MODEL_VERSION = '0.4.0'  # Adds default dispatch across exact-revision DSoftBus and AccessToken profiles.
SINK_MODEL_VERSION = '0.6.0'  # Adds public OH_LOG macros and direct message output APIs.

DSOFTBUS_COMMIT = '0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132'

@dataclass(frozen=True)
class SensitiveSourceModel:
    repository: str
    commit: str
    # Exact record type -> sensitive material field, never len/index/iv.
    fields: tuple = (('SessionKey', 'value'), ('AesGcmCipherKey', 'key'),
                     ('AesGcm128CipherKey', 'key'), ('AesCtrCipherKey', 'key'))
    # Explicit metadata fields that do not carry key material in the reviewed record.
    non_sensitive_fields: tuple = (('SessionKey', ('len',)),)
    output_calls: tuple = (('SoftBusGenerateSessionKey', 0),)
    # File/function/parameter-index, bound to reviewed callback semantics.
    parameters: tuple = (('core/authentication/src/auth_hichain.c', 'OnSessionKeyReturned', 1),)
    provenance: str = 'Reviewed pinned dsoftbus key declarations; research model, not product policy'
    additional_sinks: tuple = ()

@dataclass(frozen=True)
class ExposureSinkModel:
    name: str
    format_index: int
    default_private: bool = True
    # Optional exact source paths for ambiguous short macro names such as LOGI.
    files: tuple = ()

_SOFTBUS_LOG_FAMILIES = ('AUTH', 'TRANS', 'COMM', 'LNN', 'CONN', 'DISC')
_SOFTBUS_GUARD_LEVELS = {
    'AUTH': ('E', 'W'), 'TRANS': ('E', 'W', 'D'),
    'COMM': ('E', 'W'), 'LNN': ('E', 'W'),
    'CONN': ('E', 'W', 'I', 'D'), 'DISC': ('E', 'W', 'D'),
}
SINKS = (
    tuple(ExposureSinkModel(family+'_LOG'+level, 1)
          for family in _SOFTBUS_LOG_FAMILIES for level in 'FEWID') +
    tuple(ExposureSinkModel(family+'_CHECK_AND_RETURN_RET_LOG'+level, 3)
          for family, levels in _SOFTBUS_GUARD_LEVELS.items() for level in levels) +
    tuple(ExposureSinkModel(family+'_CHECK_AND_RETURN_LOG'+level, 2)
          for family, levels in _SOFTBUS_GUARD_LEVELS.items() for level in levels) +
    tuple(ExposureSinkModel(name, 1) for family in ('DFILE', 'DFINDER')
          for name in (family+'_LOG'+level for level in 'FEWID')) +
    tuple(ExposureSinkModel('FILLP_LOG'+level, 0)
          for level in ('ERR', 'WAR', 'INF', 'DTL', 'DBG', 'BUTT')) +
    (ExposureSinkModel('HiLogPrint', 4), ExposureSinkModel('HiLogBasePrint', 4),
     ExposureSinkModel('OH_LOG_Print', 4),
     ExposureSinkModel('OH_LOG_PrintMsg', 4),
     ExposureSinkModel('OH_LOG_PrintMsgByLen', 5),
     ExposureSinkModel('HILOG_IMPL', 4)) +
    tuple(ExposureSinkModel('OH_LOG_' + level, 1) for level in
          ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')) +
    tuple(ExposureSinkModel('HILOG_' + level, 1) for level in
          ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')) +
    tuple(ExposureSinkModel('HILOG_BASE_' + level, 1) for level in
          ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')) +
    tuple(ExposureSinkModel('HILOG_COMM_' + level, 0) for level in
          ('INFO', 'WARN', 'ERROR', 'FATAL')) +
    tuple(ExposureSinkModel('HiLog' + level.title(), 1) for level in
          ('debug', 'info', 'warn', 'error', 'fatal')))


DEFAULT_SOURCE = SensitiveSourceModel('openharmony/communication_dsoftbus', DSOFTBUS_COMMIT)

ACCESS_TOKEN_COMMIT = '3be426c558613e7c7af92a591c2bfaeb6af06b60'
_ACCESS_TOKEN_FILE = 'interfaces/innerkits/accesstoken/src/accesstoken_kit.cpp'
ACCESS_TOKEN_SOURCE = SensitiveSourceModel(
    'openharmony/security_access_token', ACCESS_TOKEN_COMMIT,
    fields=(), non_sensitive_fields=(), output_calls=(),
    parameters=(
        (_ACCESS_TOKEN_FILE, 'AccessTokenKit::GetKernelPermissions', 0),
        (_ACCESS_TOKEN_FILE, 'AccessTokenKit::GetReqPermissionByName', 0),
        (_ACCESS_TOKEN_FILE, 'AccessTokenKit::IsAtomicServiceByFullTokenID', 0),
        (_ACCESS_TOKEN_FILE, 'AccessTokenKit::SetPermissionStatusWithPolicy', 0),
    ),
    provenance=(
        'Exact-revision AccessTokenID/FullTokenID API inputs identify authorization principals; '
        'they are not bearer secrets. Candidate status asks whether disclosure violates the '
        'product privacy/threat model; logging identity alone does not establish impact.'
    ),
    additional_sinks=tuple(
        ExposureSinkModel('LOG'+level, 2, files=(_ACCESS_TOKEN_FILE,))
        for level in 'FEWID'
    ),
)

# Default detector dispatch is limited to reviewed exact repository/commit profiles.
SUPPORTED_SOURCE_MODELS = (DEFAULT_SOURCE, ACCESS_TOKEN_SOURCE)
