"""DATA-06, CWE-131: parcel-derived typed allocation width.

The rule recognizes one narrowly scoped Cangjie FFI MessageSequence reader:
the parcel count is checked against parcel bytes, then used as a byte count
for typed arrays that are indexed for that count. Parcel readability does not
establish the capacity of these separate output allocations.
"""

FAMILY = "DATA-06"
TITLE = "parcel-derived typed allocation width"
CWE = "CWE-131"
RULES = ("ipc.parcel.array-allocation-width",)
