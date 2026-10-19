"""DATA-02, CWE-20: parcel length and index bounds beyond memcpy.

Entry -> effect: a length or index read out of the request parcel drives a
memory access, and the bound that would have to match the *destination* is not
established on the path.

Two shapes, because the memory operation differs:

* `ipc.parcel.bounds` -- the parcel-derived value selects from a buffer (an
  index), or is used as the size of a parcel read, without a matched upper
  bound against that buffer's stated capacity (and, for a signed value, without
  a non-negative check).
* `ipc.parcel.write-bounds` -- `ReadRawData(destination, size)` writes `size`
  bytes out of the parcel into a caller-provided destination. Its size is
  argument 1, not the memcpy position, and the destination's capacity has to be
  stated by a declaration in the analysed function for the question to be
  decidable at all.

A bound checked against another buffer, or against the parcel's own remaining
size rather than the destination, does not satisfy the criterion. A destination
whose capacity the source does not state leaves the question open, not answered.
"""

FAMILY = "DATA-02"
TITLE = "parcel-derived index and destination bounds"
CWE = "CWE-20"
RULES = (
    "ipc.parcel.bounds",
    "ipc.parcel.write-bounds",
)
