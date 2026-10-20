"""AUTH-06, CWE-862: peer session identity needs an allowlist before effects."""

FAMILY = "AUTH-06"
TITLE = "network-auth callback session-name allowlist"
CWE = "CWE-862"
RULES = ("ipc.network.auth-session-whitelist",)
