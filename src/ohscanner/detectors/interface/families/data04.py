"""DATA-04, CWE-200: sensitive result reaches the caller-visible reply.

Entry -> effect: a disclosure-class call produces a value, and the path writes
it into the reply parcel without a matched caller authorization. The reply is
the caller-visible output of the transaction, so the data-flow edge -- source
call to reply write -- is what makes the value an exposure candidate; the read
API alone is not.

The rule needs both ends to be modelled: the call has to be in the reviewed
disclosure catalogue, and the write has to target the reply parcel (a second
`MessageParcel` parameter), not the request or an arbitrary parcel. A path whose
guard was matched before the write is a control, and a value produced by a call
outside the catalogue is not a source.
"""

FAMILY = "DATA-04"
TITLE = "sensitive result written to the reply parcel"
CWE = "CWE-200"
RULES = ("ipc.data.sensitive-flow",)
