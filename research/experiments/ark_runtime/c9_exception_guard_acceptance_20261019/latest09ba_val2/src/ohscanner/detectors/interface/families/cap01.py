"""CAP-01, CWE-926: capability export.

Entry -> effect: a `WriteRemoteObject` or `WriteFileDescriptor` puts an object
reference or a file descriptor into the reply of a caller-reachable handler, so a
capability can leave the party that was authorized to hold it.

The criterion is that the authorization of the *original* caller covers the
export path. An export inside a handler that anyone reaching the entry can invoke
is the case this family reports; the same export behind a caller check that
covers it is not. A descriptor written back to the caller that owns it is not an
export, and the rule does not attempt to prove that a given object is reachable
by an unauthorized principal -- that stays an evidence obligation.
"""

FAMILY = "CAP-01"
TITLE = "capability export"
CWE = "CWE-926"
RULES = ("ipc.capability.export",)
