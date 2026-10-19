"""AUTH-04, CWE-863: authorization-path coverage.

Entry -> effect: an authorization result is computed, but the paths that should
be stopped by it reach a sensitive operation anyway -- the refusal branch falls
through instead of returning, or a dispatch case is reachable without passing the
check at all.

The criterion is per path, not per check: for every reachable sensitive case the
check has to dominate it, and the refusal has to actually leave the function. A
present-but-uncovered check is what this family reports; a path with no check at
all is AUTH-02, and a check answered about the wrong principal is AUTH-03. The
three are kept apart so a reader can tell "missing", "wrong subject" and
"present but not covering" apart instead of reading them as one bucket.
"""

FAMILY = "AUTH-04"
TITLE = "authorization-path coverage"
CWE = "CWE-863"
RULES = ("ipc.auth.guard-coverage",)
