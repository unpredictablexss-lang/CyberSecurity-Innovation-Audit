"""Versioned, explicit OH IPC models. Names alone never establish authorization.

This narrow catalog is an auditable starting policy, not all OpenHarmony APIs.
Additional components should supply reviewed exact-name models via IpcPolicy.
"""
from dataclasses import dataclass, field
from typing import FrozenSet, Tuple

MODEL_VERSION = "oh-ipc-2026.10-v1"

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

    def __post_init__(self):
        if self.max_call_depth < 0 or self.max_call_depth > 4:
            raise ValueError("max_call_depth must be between 0 and 4")
        if self.max_paths < 2 or self.max_paths > 1024:
            raise ValueError("max_paths must be between 2 and 1024")
