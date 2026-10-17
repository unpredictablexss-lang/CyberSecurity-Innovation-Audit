"""Versioned, explicit OH IPC models. Names alone never establish authorization.

This narrow catalog is an auditable starting policy, not all OpenHarmony APIs.
Additional components should supply reviewed exact-name models via IpcPolicy.
"""
from dataclasses import dataclass, field
from typing import FrozenSet, Tuple

MODEL_VERSION = "oh-ipc-2026.10-v8"

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
    "ipc.parcel.bounds": "out_of_bounds_read",
    "ipc.parcel.write-bounds": "out_of_bounds_write",
    "ipc.parcel.lifecycle": "use_after_release",
    "ipc.auth.flow": "identity_confusion",
    "ipc.data.sensitive-flow": "information_disclosure",
    "ipc.capability.export": "capability_exposure",
}

# Only the consequences whose CWE the catalogue can actually justify carry one.
# The rest are impacts whose CWE depends on what the path reaches, so asserting a
# number would be over-claiming; they are named without a CWE instead.
IMPACT_CWE = {
    "information_disclosure": "CWE-200",
    "out_of_bounds_read": "CWE-125",
    "out_of_bounds_write": "CWE-787",
    "use_after_release": "CWE-416",
    "capability_exposure": "CWE-668",
}

IMPACT_DESCRIPTION = {
    "information_disclosure": "data the caller is not entitled to read may be returned to it",
    "out_of_bounds_read": "an out-of-bounds read may return adjacent memory to the caller",
    "out_of_bounds_write": "an out-of-bounds write may corrupt memory adjacent to the destination",
    "use_after_release": "memory the parcel owns may be read after the parcel released or moved it",
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


def reviewed_consequence(impact):
    """Return `impact` only if this catalogue reviewed it, else `None`.

    A consequence that reaches the public schema has to come from an explicit,
    reviewed list -- never from a message string or a name heuristic (contract v2
    §3). `"unknown"` is the catalogue's own way of saying "this rule has no
    modelled consequence", so it becomes `None` rather than travelling as a value
    a downstream consumer could mistake for a classified category.
    """
    if impact is None or impact == "unknown":
        return None
    if impact not in IMPACT_DESCRIPTION:
        raise ValueError("unreviewed consequence class: " + str(impact))
    return impact


# The catalogue must be internally consistent: a rule may not map to an impact
# that IMPACT_DESCRIPTION does not describe, and no CWE may be attached to an
# impact the catalogue never names. This fails at import rather than at the first
# finding, which is where a typo would otherwise surface as a KeyError mid-scan.
assert set(IMPACT_BY_RULE.values()) <= set(IMPACT_DESCRIPTION), sorted(
    set(IMPACT_BY_RULE.values()) - set(IMPACT_DESCRIPTION))
assert set(IMPACT_CWE) <= set(IMPACT_DESCRIPTION), sorted(
    set(IMPACT_CWE) - set(IMPACT_DESCRIPTION))


@dataclass(frozen=True)
class ServiceAccountRole:
    """A caller UID a reviewed source assigns to a named service account.

    Deliberately not a `trusted_uids` entry. `trusted_uids` is read as
    authorization wherever a calling UID is compared with it, so adding a value
    there credits every guard that names it, in every component, for every
    operation -- which is the generalization this record exists to avoid. An
    account is not a permission and not a general caller role, so an entry names
    the operations that account's role authorizes, the constant a guard has to
    compare against, and the value the scanned definitions have to bind that
    constant to.

    Nothing here is credited from a name. The constant has to resolve, in the
    scanned sources, to a definition whose literal is `uid`; a same-named constant
    bound to something else is a different guard, and a value written without a
    definition has no binding a reviewer can check.
    """

    constant: str                        # the name a guard compares the calling UID with
    uid: str                             # the value the reviewed definitions bind it to
    role: str                            # the fact derived, e.g. "<caller-account:...>"
    accepted_operations: Tuple[str, ...]  # operations this role authorizes, and no others
    origin: str                          # the reviewed source of the account assignment


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
    # Copy calls whose length argument is positional in their own signature.
    # `ReadRawData` and `ReadBuffer` are deliberately absent: their lengths sit at
    # different positions, and reading the parcel API by the memcpy shape is what
    # made a `ReadRawData(dst, len)` length look like argument 2 (the argument
    # after it) and drop the call entirely. They are modelled below instead.
    copy_calls: FrozenSet[str] = frozenset({"memcpy", "memmove", "memcpy_s", "memmove_s"})
    # `ReadRawData(void *data, int32_t size)` copies `size` bytes out of the
    # parcel into a caller-provided destination; `(destination, size)` is the
    # whole signature and the size is argument 1.
    parcel_dest_reads: FrozenSet[str] = frozenset({"ReadRawData"})
    # `ReadBuffer(size_t length)` returns a pointer into the parcel's own buffer
    # for `length` bytes. The pointer is a view, not a copy: the parcel stays its
    # owner, so any later operation that releases or rewinds that buffer leaves
    # the pointer dangling.
    parcel_view_calls: FrozenSet[str] = frozenset({"ReadBuffer"})
    parcel_invalidating_calls: FrozenSet[str] = frozenset({"Reuse", "RewindRead", "SetReadPosition", "Seek"})
    # Right-hand-side writers of the reply parcel. A modelled sensitive result
    # handed to one of these is the point where it becomes visible to the caller.
    reply_write_calls: FrozenSet[str] = frozenset({
        "WriteInt8", "WriteInt16", "WriteInt32", "WriteInt64",
        "WriteUint8", "WriteUint16", "WriteUint32", "WriteUint64",
        "WriteFloat", "WriteDouble", "WriteBool", "WriteChar",
        "WriteString", "WriteString16", "WriteStringVector", "WriteBuffer",
        "WriteRawData", "WriteParcelable", "WriteParcelableVector", "WriteByteArray",
        "WriteRemoteObject", "WriteFileDescriptor", "WriteInterfaceToken", "WriteVector",
    })
    entry_names: FrozenSet[str] = frozenset({"OnRemoteRequest", "OnRemoteMessageRequest"})
    caller_class_sensitive_calls: FrozenSet[str] = frozenset({"GetReqPermissions", "StartUsingPermissionCallback", "RemovePermissionUsedRecords", "GetPermissionUsedRecordsAsync", "IsAllowedUsingPermission", "SetMutePolicy"})
    # Reviewed caller-role authorization predicates, by exact name: `(name, kind,
    # label)`. Each answers whether the *caller* holds a privileged role and none
    # takes a permission argument, so a path carrying one is not a path carrying a
    # permission check -- `auth` facts name a permission, `caller_class` facts name
    # a role, and conflating them would let a role question satisfy a permission
    # one. Read only for a call this file does not itself define: a locally written
    # function of the same name is interpreted, never assumed to be the framework's.
    caller_role_guards: Tuple[Tuple[str, str, str], ...] = (
        ("IsSystemCalling", "caller_class", "<system-caller>"),
        ("IsSACalling", "caller_class", "<sa-caller>"),
        ("IsShellCall", "caller_class", "<shell-caller>"),
        ("IsSystemAppCalling", "caller_class", "system_app"),
        ("CheckCallerIsSystemApp", "caller_class", "system_app"),
        # Kept identical to the facts a helper summary derives for these two names
        # (`<trusted-uid>` / TOKEN_NATIVE), so the same predicate is one identity
        # whether it is called directly or reached through a local helper.
        ("IsRootCalling", "auth", "<trusted-uid>"),
        ("IsNativeProcessCalling", "caller_class", "TOKEN_NATIVE"),
        ("IsPrivilegedCalling", "auth", "<caller-service-role>"),
        ("IsAccessTokenCalling", "auth", "<caller-service-role>"),
    )
    # Explicit caller-supplied reviewed account models only. The default remains
    # empty: a named constant/value alone is not an approved account assignment.
    service_account_roles: Tuple[ServiceAccountRole, ...] = ()
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
