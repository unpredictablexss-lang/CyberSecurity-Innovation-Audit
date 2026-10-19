"""DATA-04: reviewed sensitive results reach the caller-visible reply."""

FAMILY = "DATA-04"
TITLE = "sensitive result written to the IPC reply"
CWE = "CWE-200"
RULES = ("ipc.data.sensitive-flow",)

# The two output references are part of this exact AppMgr API signature. The
# implementation writes bundleName and uid, which the IPC stub later serializes.
# Do not infer source taint for arbitrary reference parameters or methods.
POLICY = {
    "disclosure_output_calls": (("GetBundleNameByPid", (1, 2)),),
}
