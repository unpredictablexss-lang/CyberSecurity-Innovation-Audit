"""Explicit source/sink models; no sensitive-name heuristics or catalog registration."""
from dataclasses import dataclass

SOURCE_MODEL_VERSION = '0.4.0'  # Frozen D3/D4 source semantics; new profiles are append-only.
SOURCE_PROFILE_CATALOG_VERSION = '0.1.0'
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
    # (function, source_arg, destination_arg, arity) for reviewed encoders.
    copy_calls: tuple = ()
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
IOTC_COMMIT = 'd8c0aef305601770c912dbdedc58a3f1e6efd30c'
_IOTC_LOCAL_CTL_FILE = 'core/wifi/application/local_control/local_ctl_coap_api.c'
IOTC_LOCAL_CONTROL_SOURCE = SensitiveSourceModel(
    'openharmony/communication_iot_connect', IOTC_COMMIT,
    fields=(), non_sensitive_fields=(), output_calls=(
        ('IotcPkcs5Pbkdf2Hmac', 1, 3),
    ),
    copy_calls=(('UtilsHexify', 0, 2, 4),),
    provenance=(
        'Pinned communication_iot_connect source at d8c0aef3: the reviewed PBKDF2 API '
        'writes derived key bytes to argument 1, UtilsHexify copies those bytes as hex '
        'to argument 2, and IOTC_LOGI routes its format to a public HiLog string sink. '
        'The component authCode identity and product log visibility/impact remain unknown.'
    ),
    additional_sinks=(
        ExposureSinkModel(
            'IOTC_LOGI', 0, default_private=False, files=(_IOTC_LOCAL_CTL_FILE,)
        ),
    ),
)
SUPPORTED_SOURCE_MODELS = (DEFAULT_SOURCE, ACCESS_TOKEN_SOURCE, IOTC_LOCAL_CONTROL_SOURCE)
