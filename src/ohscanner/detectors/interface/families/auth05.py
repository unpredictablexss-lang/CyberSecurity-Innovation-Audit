"""AUTH-05, CWE-863: calling-identity flow across an identity change point.

Entry -> effect: the entry authorizes the caller, then replaces the calling
identity (`ResetCallingIdentity`), and performs a sensitive operation before the
saved identity is restored. The guard and the effect name different principals:
the authorization was computed for the original caller, while the operation runs
under the service's identity.

Keeping this separate from AUTH-02/AUTH-04 matters. AUTH-02 is "no guard on the
path", AUTH-04 is "a guard exists but does not cover this path", and this family
is "a guard covers this path but the principal changed after it". The same pair
may be legitimate when the service is deliberately acting on the caller's behalf
and the saved identity is restored before returning; that is exactly why a
finding here is a candidate with an obligation to review the identity protocol,
not a conclusion.
"""

FAMILY = "AUTH-05"
TITLE = "calling-identity change after authorization"
CWE = "CWE-863"
RULES = ("ipc.auth.flow",)
