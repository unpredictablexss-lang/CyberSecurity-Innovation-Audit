"""Explicit source/sink models; no sensitive-name heuristics or catalog registration."""
from dataclasses import dataclass

SOURCE_MODEL_VERSION = '0.4.0'  # Frozen D3/D4 source semantics; new profiles are append-only.
SOURCE_PROFILE_CATALOG_VERSION = '0.2.0'
SINK_MODEL_VERSION = '0.8.0'  # Adds reviewed CM_LOG variadic logging macros.

DSOFTBUS_COMMIT = '0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132'
DSOFTBUS_CURRENT_COMMIT = '9f922677e147b939d6db899bde181d609d64711b'

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
    # Exact reviewed cleanup APIs consume/clear bytes but are not exposure sinks.
    non_escaping_calls: tuple = ()

@dataclass(frozen=True)
class ExposureSinkModel:
    name: str
    format_index: int
    default_private: bool = True
    # Optional exact source paths for ambiguous short macro names such as LOGI.
    files: tuple = ()
    supports_privacy_markers: bool = True

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
    tuple(ExposureSinkModel('WIFI_LOG' + level, 0) for level in 'FEWID') +
    tuple(ExposureSinkModel('OH_LOG_' + level, 1) for level in
          ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')) +
    tuple(ExposureSinkModel('HILOG_' + level, 1) for level in
          ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')) +
    tuple(ExposureSinkModel('HILOG_BASE_' + level, 1) for level in
          ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')) +
    tuple(ExposureSinkModel('HILOG_COMM_' + level, 0) for level in
          ('INFO', 'WARN', 'ERROR', 'FATAL')) +
    tuple(ExposureSinkModel('HiLog' + level.title(), 1) for level in
          ('debug', 'info', 'warn', 'error', 'fatal')) +
    tuple(ExposureSinkModel('CM_LOG_' + level, 0, default_private=level == 'D',
                           supports_privacy_markers=False) for level in 'IWED'))


# These JS/ANI APIs return status values; some also populate an output object.
# The call-site remains an unresolved escape candidate; only the status value
# itself is prevented from inheriting the secret argument's taint.
STATUS_RETURN_CALLS = frozenset({
    'napi_set_named_property',
    'napi_set_property',
    'napi_define_properties',
    'env->Object_SetPropertyByName_Ref',
    'env->Object_SetPropertyByName_Int',
    'AniUtils::GenerateCredentialObj',
})

DEFAULT_SOURCE = SensitiveSourceModel(
    'openharmony/communication_dsoftbus', DSOFTBUS_COMMIT,
    non_escaping_calls=('SoftBusFree', 'memset_s'))
# This exact newer tree was checked against the same source contract: SessionKey.value
# and AES key fields still contain key bytes; OnSessionKeyReturned arg 1 receives
# the key; SoftBusGenerateSessionKey writes bytes through arg 0. This adds only
# exact-commit eligibility and does not generalize the profile to other revisions.
DSOFTBUS_CURRENT_SOURCE = SensitiveSourceModel(
    'openharmony/communication_dsoftbus', DSOFTBUS_CURRENT_COMMIT,
    fields=DEFAULT_SOURCE.fields,
    non_sensitive_fields=DEFAULT_SOURCE.non_sensitive_fields,
    output_calls=DEFAULT_SOURCE.output_calls,
    copy_calls=DEFAULT_SOURCE.copy_calls,
    parameters=DEFAULT_SOURCE.parameters,
    provenance=(
        'Exact source contract reviewed at communication_dsoftbus commit 9f922677: '
        'SessionKey.value and AES key fields are material, OnSessionKeyReturned '
        'argument 1 carries the session key, and SoftBusGenerateSessionKey writes '
        'to argument 0. This is a static component model, not product exposure proof.'
    ),
    additional_sinks=DEFAULT_SOURCE.additional_sinks,
    non_escaping_calls=DEFAULT_SOURCE.non_escaping_calls,
)

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
SUPPORTED_SOURCE_MODELS = (DEFAULT_SOURCE, DSOFTBUS_CURRENT_SOURCE, ACCESS_TOKEN_SOURCE, IOTC_LOCAL_CONTROL_SOURCE)
