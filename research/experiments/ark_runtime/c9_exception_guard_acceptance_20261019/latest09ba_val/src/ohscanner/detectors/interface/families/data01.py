"""DATA-01, CWE-20: Parcel length and read position.

Entry -> effect: a length, capacity or offset read out of an incoming Parcel
drives a copy or a read, so the caller of the service controls how much is read
and from where.

Two rule ids, one per way the arithmetic fails:

* `ipc.parcel.copy-range` -- a length taken from the request is used as a copy
  bound without being checked non-negative and within the capacity of the same
  destination.
* `ipc.parcel.position-underflow` -- a subtraction on a position or remaining
  length is performed before establishing that enough was left to subtract.

The criterion is that both operands belong to the same destination. A bound
checked against a different buffer, or a length taken from a different read than
the one that produced the pointer, does not satisfy it.
"""

FAMILY = "DATA-01"
TITLE = "parcel length and read position"
CWE = "CWE-20"
RULES = (
    "ipc.parcel.copy-range",
    "ipc.parcel.position-underflow",
)
