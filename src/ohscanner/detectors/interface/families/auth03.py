"""AUTH-03, CWE-863: caller identity, ownership and caller class.

Entry -> effect: an operation whose authorization depends on *which* principal is
calling -- the caller token/UID, the process asking for itself, an ID read out of
the request Parcel, or the owner of the object touched -- and which reaches the
operation without that question being answered about the right principal.

Five rule ids, one per way the question goes wrong:

* `ipc.auth.caller-class` -- an operation restricted to one caller category (a
  system caller, a system app, a native process) runs for another.
* `ipc.auth.object-owner` -- the object or session acted on belongs to a
  different principal than the caller.
* `ipc.auth.identity-domain` -- a caller identifier is matched against a domain
  it does not belong to (a UID compared with a TokenID, a full token with a
  plain one).
* `ipc.auth.service-identity` -- the operation is performed under a service or
  process identity other than the original caller's.
* `ipc.auth.request-identity` -- the identity is taken from a value the caller
  wrote into the request rather than from the caller's own token.

A guard on one of these channels answers only that channel: a role question does
not satisfy a permission question, and a TokenID comparison does not establish a
UID comparison.
"""

FAMILY = "AUTH-03"
TITLE = "caller identity, ownership and caller class"
CWE = "CWE-863"
RULES = (
    "ipc.auth.caller-class",
    "ipc.auth.object-owner",
    "ipc.auth.identity-domain",
    "ipc.auth.service-identity",
    "ipc.auth.request-identity",
)

# CVE-2024-12082 discloses that AppMgrServiceInner::GetBundleNameByPid is
# restricted to system-ability callers. Keep this exact contract scoped to its
# owning repository and require the gate to precede the PID-to-record lookup.
# This is a reviewed API contract, not a CVE-name rule.
POLICY = {
    "repository_caller_class_contracts": (
        ("openharmony/ability_ability_runtime",
         "AppMgrServiceInner::GetBundleNameByPid",
         "<sa-caller>",
         ("GetAppRunningRecordByPid",)),
    ),
}
