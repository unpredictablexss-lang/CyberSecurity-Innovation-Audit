"""AUTH-02, CWE-862: missing server-side authorization.

A reviewed entry reaches a modeled sensitive operation without a matched guard
on the original caller. A client-side check or a check on another operation does
not establish server-side authorization for this path.
"""

FAMILY = "AUTH-02"
TITLE = "missing server-side authorization"
CWE = "CWE-862"
RULES = ("ipc.auth.missing",)

# No default service-account authorization is approved by this integration.
# ACCESSTOKEN_UID=3020 proves a source value, not its account ownership or its
# authority for a product operation. Explicit fixture policies test the engine;
# product activation requires a separate source-bound review.
POLICY = {}
