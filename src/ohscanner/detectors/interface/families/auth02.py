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
RULES = ("ipc.auth.missing",)

# The access-token service: the three ITokenSyncCallback operations are the ones
# that interface exists to serve, so the UID comparison inside
# `TokenSyncCallbackStub` is that interface's admission test -- and those three
# operations are the only ones that accept the role, which is what keeps one
# service's account from authorizing everything behind a guard that happens to
# name it. See `models.ServiceAccountRole` for why this is not a `trusted_uids`
# entry, and `analysis.Interpreter.account_role` for the three conditions a
# guard has to meet before the role is credited.
POLICY = {
    "service_account_roles": (
        ServiceAccountRole(
            constant="ACCESSTOKEN_UID",
            uid="3020",
            role="<caller-account:access-token-service>",
            accepted_operations=("GetRemoteHapTokenInfo", "DeleteRemoteHapTokenInfo",
                                 "UpdateRemoteHapTokenInfo"),
            origin="access-token service account, ACCESSTOKEN_UID = 3020 (reviewed account "
                   "assignment, 2026-10-16); the value is confirmed against the scanned "
                   "definitions, the account assignment is the reviewed claim it carries",
        ),
    ),
}
