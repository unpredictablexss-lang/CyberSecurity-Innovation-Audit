"""DATA-03, CWE-416: parcel-backed view lifetime.

Entry -> effect: `ReadBuffer(length)` hands out a pointer into the parcel's own
buffer. The parcel keeps ownership; the pointer is a view, not a copy. A later
`Reuse`, `RewindRead`, `SetReadPosition` or `Seek` on the same parcel releases
or moves that buffer, and a read through the pointer afterwards has no live
owner on the path.

The rule is per path: a view that is copied out before the parcel is reused is
not a candidate, and a parcel that is never reused is not one either. Views are
tracked by the variable that holds them and matched to the parcel they came
from; a view whose producing receiver is a different parcel is never marked by
an operation on this one.
"""

FAMILY = "DATA-03"
TITLE = "parcel buffer view lifetime"
CWE = "CWE-416"
RULES = ("ipc.parcel.lifecycle",)
