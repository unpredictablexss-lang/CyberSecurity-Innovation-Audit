"""AUTH-01, CWE-441: the system-ability / descriptor trust boundary.

Entry -> effect: an `OnRemoteRequest` reads a request Parcel that carries a
system-ability or descriptor token, and the stub then dispatches, relays or calls
back on the strength of what that Parcel says.

The criterion is a comparison of that token with the descriptor of the interface
this class itself states it implements, and a refusal of the paths where they do
not match. A comparison against some other interface -- or against a descriptor
whose identity the analysed sources never state -- is reported with that reason
rather than counted as a guard or as a proven mismatch: neither a working guard
nor a bypass is established from a name alone.
"""

FAMILY = "AUTH-01"
TITLE = "system-ability and descriptor trust at the dispatch boundary"
CWE = "CWE-441"
RULES = ("ipc.relay.descriptor-boundary",)
