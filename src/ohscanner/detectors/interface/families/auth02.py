"""AUTH-02, CWE-862: missing server-side authorization.

Entry -> effect: a reviewed entry or handler reaches a sensitive API or a device
object with no server-side check on the original caller.

The criterion is that a permission or trusted-caller fact about the *original*
caller covers the path to the operation. A check written only in a client NAPI
wrapper does not satisfy it -- it constrains the client, not the server -- and
neither does a guard on a different operation of the same stub.

This family also owns the reviewed *service-account* role below. An account is
not a permission: `trusted_uids` is read as authorization wherever a calling UID
is compared with it, so adding a value there would credit every guard naming it,
in every component, for every operation. The record instead names the constant a
guard must compare the calling UID with, the value the scanned definitions must
bind that constant to, and the operations that account's role authorizes -- and
no others. Nothing here is credited from a name: the constant has to resolve, in
the scanned sources, to a definition whose literal is `uid`.
"""

from ..models import ServiceAccountRole

FAMILY = "AUTH-02"
TITLE = "missing server-side authorization"
CWE = "CWE-862"
RULES = ("ipc.auth.missing", "ipc.auth.privileged-app-bypass")

# The access-token service account is scoped to its owning repository. The three
# ITokenSyncCallback operations are guarded by its UID comparison. PrivacyManager
# also has one explicit exception: RemovePermissionUsedRecords skips the permission
# check only for IsAccessTokenCalling(). The role is credited for that exact
# operation only; it is not a general exemption for the rest of PrivacyManager.
# See `models.ServiceAccountRole` and `analysis.Interpreter.account_role` for the
# source binding and repository boundary required before this fact is credited.
POLICY = {
    "service_account_roles": (
        ServiceAccountRole(
            constant="ACCESSTOKEN_UID",
            uid="3020",
            role="<caller-account:access-token-service>",
            repository="openharmony/security_access_token",
            accepted_operations=("GetRemoteHapTokenInfo", "DeleteRemoteHapTokenInfo",
                                 "UpdateRemoteHapTokenInfo", "RemovePermissionUsedRecords"),
            origin="access-token service account, ACCESSTOKEN_UID = 3020 (reviewed account "
                   "assignment; privacy.cfg assigns privacy_service to uid access_token and "
                   "grants PERMISSION_USED_STATS; the stub explicitly bypasses that permission "
                   "only for this operation when IsAccessTokenCalling() is true. The literal "
                   "is still confirmed against scanned definitions",
            operation_handlers=(("RemovePermissionUsedRecords",
                                 "PrivacyManagerStub::RemovePermissionUsedRecordsInner"),),
        ),
    ),
}
