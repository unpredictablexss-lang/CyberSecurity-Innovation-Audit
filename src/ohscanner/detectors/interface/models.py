"""Versioned, explicit OH IPC models. Names alone never establish authorization.

This narrow catalog is an auditable starting policy, not all OpenHarmony APIs.
Additional components should supply reviewed exact-name models via IpcPolicy.
"""
from dataclasses import dataclass, field
from typing import FrozenSet, Tuple

MODEL_VERSION = "oh-ipc-2026.10-v1"

# ---------------------------------------------------------------------------
# Reviewed consequence catalogue (v1), kept separate from the mechanism rules.
#
# A mechanism rule says *how* a trust boundary fails. This says what the failure
# can expose, which is scored separately (completeness, and CWE accuracy: the
# mechanism CWE and the consequence CWE are different answers).
#
# Every entry is a possibility attached to a candidate, never a proven effect.
# Calling a sensitive read API does not establish that an unauthorized caller
# reached it, nor that anything was returned to anyone.
# ---------------------------------------------------------------------------

# Sensitive operations whose effect is to *return* data or capability to the
# caller. A finding that reaches one of these may expose information whatever the
# mechanism was, which is why the disclosure consequence is not tied to one
# family: 15 of the 39 advisory records in the corpus name information disclosure
# as the official impact, spread over AUTH-02, AUTH-03, AUTH-04 and DATA-01.
DISCLOSURE_CALLS = frozenset({
    "GetPasteData", "GetAllCallList", "GetCallState", "GetTokenInfo",
    "GetRemoteHapTokenInfo", "GetReqPermissions", "GetPermissionUsedRecordsAsync",
    "IsAllowedUsingPermission", "Dump", "ReadFile", "GetDisplaySnapshot",
    "Capture", "GetImsConfig", "GetImsFeatureValue",
    "GetUserData", "ReadUserData", "OpenUserFile",
})

# Baseline consequence per rule, for findings that do not reach a read API.
IMPACT_BY_RULE = {
    "ipc.relay.descriptor-boundary": "boundary_bypass",
    "ipc.auth.missing": "unauthorized_effect",
    "ipc.auth.guard-coverage": "unauthorized_effect",
    "ipc.auth.caller-class": "restricted_category_access",
    "ipc.auth.identity-domain": "identity_confusion",
    "ipc.auth.request-identity": "identity_confusion",
    "ipc.auth.service-identity": "identity_confusion",
    "ipc.auth.object-owner": "cross_principal_effect",
    "ipc.parcel.copy-range": "out_of_bounds_read",
    "ipc.parcel.position-underflow": "out_of_bounds_read",
    "ipc.capability.export": "capability_exposure",
}

# Only the consequences whose CWE the catalogue can actually justify carry one.
# The rest are impacts whose CWE depends on what the path reaches, so asserting a
# number would be over-claiming; they are named without a CWE instead.
IMPACT_CWE = {
    "information_disclosure": "CWE-200",
    "out_of_bounds_read": "CWE-125",
    "capability_exposure": "CWE-668",
}

IMPACT_DESCRIPTION = {
    "information_disclosure": "data the caller is not entitled to read may be returned to it",
    "out_of_bounds_read": "an out-of-bounds read may return adjacent memory to the caller",
    "capability_exposure": "an object reference, file descriptor or service capability may leave the authorized owner",
    "boundary_bypass": "a caller of one interface may reach behaviour reserved for another",
    "unauthorized_effect": "an operation intended to require authorization may run without it",
    "restricted_category_access": "an operation restricted to one caller category may run for another",
    "identity_confusion": "an operation may be attributed to or performed as the wrong principal",
    "cross_principal_effect": "an operation may act on another principal's resource or session",
    "unknown": "the consequence is not modelled for this rule",
}


def consequence_for(rule, calls=()):
    """`(impact, consequence_cwe, basis)` for a finding.

    A read-type sensitive call promotes the consequence to information
    disclosure regardless of which mechanism failed; otherwise the rule's
    baseline consequence applies. `basis` names the call that drove the
    promotion, so the classification can be reviewed rather than trusted.
    """
    for name in calls or ():
        if name in DISCLOSURE_CALLS:
            return "information_disclosure", IMPACT_CWE["information_disclosure"], name
    impact = IMPACT_BY_RULE.get(rule, "unknown")
    return impact, IMPACT_CWE.get(impact, ""), ""

@dataclass(frozen=True)
class IpcPolicy:
    sensitive_calls: FrozenSet[str] = frozenset({
        "StartAbility", "StartAbilityAsCaller", "StartAbilityByCall",
        "ConnectAbility", "Install", "Uninstall", "InstallBundle", "UninstallBundle",
        "Reboot", "RebootDevice", "FactoryReset", "StartUpdate", "Upgrade",
        "PublishCommonEvent", "Publish", "SetPasteData", "GetPasteData",
        "GetAllCallList", "GetCallState", "GetTokenInfo", "DeleteToken",
        "SetPermission", "GrantPermission", "RevokePermission", "Dump",
        "OpenFile", "DeleteFile", "ReadFile", "WriteFile", "SetAudioParameter",
        "CreateCameraDevice", "Capture", "SendRequest", "GetDisplaySnapshot",
        "GetRemoteHapTokenInfo", "DeleteRemoteHapTokenInfo", "UpdateRemoteHapTokenInfo",
        "GetReqPermissions", "StartUsingPermissionCallback", "RemovePermissionUsedRecords",
        "GetPermissionUsedRecordsAsync", "IsAllowedUsingPermission", "SetMutePolicy",
        "StartRtt", "StopRtt", "GetImsConfig", "SetImsConfig", "GetImsFeatureValue", "SetImsFeatureValue", "SetCameraZoom",
    })
    capability_calls: FrozenSet[str] = frozenset({"WriteRemoteObject", "WriteFileDescriptor"})
    boolean_permissions: FrozenSet[str] = frozenset({"CheckPermission", "VerifyPermission", "CheckCallerPermission"})
    result_permissions: FrozenSet[str] = frozenset({"VerifyAccessToken", "VerifyNativeToken"})
    caller_token_calls: FrozenSet[str] = frozenset({"GetCallingTokenID", "GetCallingFullTokenID", "GetFirstTokenID", "GetFirstCallerTokenID"})
    caller_uid_calls: FrozenSet[str] = frozenset({"GetCallingUid", "GetCallingUID"})
    self_calls: FrozenSet[str] = frozenset({"getuid", "geteuid", "GetSelfTokenID", "GetSelfTokenId"})
    trusted_uids: FrozenSet[str] = frozenset({"0", "ROOT_UID", "SYSTEM_UID", "1000"})
    owner_calls: FrozenSet[str] = frozenset({"GetOwnerUid", "GetOwnerUID", "GetResourceOwnerUid"})
    parcel_reads: FrozenSet[str] = frozenset({"ReadInt32", "ReadUint32", "ReadUint8", "ReadInt8", "ReadInt64", "ReadUint64", "ReadUint16", "ReadInt16", "ReadString", "ReadString16", "ReadBuffer", "ReadRawData", "ReadRemoteObject", "ReadFileDescriptor"})
    copy_calls: FrozenSet[str] = frozenset({"memcpy", "memmove", "memcpy_s", "memmove_s", "ReadRawData", "ReadBuffer"})
    entry_names: FrozenSet[str] = frozenset({"OnRemoteRequest", "OnRemoteMessageRequest"})
    caller_class_sensitive_calls: FrozenSet[str] = frozenset({"GetReqPermissions", "StartUsingPermissionCallback", "RemovePermissionUsedRecords", "GetPermissionUsedRecordsAsync", "IsAllowedUsingPermission", "SetMutePolicy"})
    service_entries: FrozenSet[str] = frozenset({"HCameraService::CreateCameraDevice", "BgContinuousTaskMgr::RequestBackgroundRunningForInner",
        "CallManagerService::StartRtt", "CallManagerService::StopRtt",
        "CallManagerService::GetImsConfig", "CallManagerService::SetImsConfig",
        "CallManagerService::GetImsFeatureValue", "CallManagerService::SetImsFeatureValue",
        "CallManagerService::SetCameraZoom"})
    transport_entries: FrozenSet[str] = frozenset({"TraceServerReceieve"})
    max_call_depth: int = 2
    max_paths: int = 96
    expected_permissions: Tuple[Tuple[str, str], ...] = ()
    object_sensitive_calls: FrozenSet[str] = frozenset({"OpenUserFile", "GetUserData", "DeleteUserData", "ReadUserData"})
    # Bounded macro expansion (cpp_macros). It is a coverage/accuracy switch, not a
    # verdict switch: every finding it changes is still a candidate, and what it
    # refused is reported. Off means every unit is parsed exactly as written.
    expand_macros: bool = True
    max_macro_sources: int = 400
    max_macro_source_bytes: int = 6_000_000

    def __post_init__(self):
        if self.max_call_depth < 0 or self.max_call_depth > 4:
            raise ValueError("max_call_depth must be between 0 and 4")
        if self.max_paths < 2 or self.max_paths > 1024:
            raise ValueError("max_paths must be between 2 and 1024")
        if self.max_macro_sources < 0 or self.max_macro_sources > 100_000:
            raise ValueError("max_macro_sources must be between 0 and 100000")
        if self.max_macro_source_bytes < 0 or self.max_macro_source_bytes > 256_000_000:
            raise ValueError("max_macro_source_bytes must be between 0 and 256000000")
