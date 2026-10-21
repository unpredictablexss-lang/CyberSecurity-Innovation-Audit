// A relay look-ahead reads a handler body to find the descriptor comparison that
// would make the hop safe. That read starts from the state preceding the
// handler's own guard, so a sensitive call met on the way is not reachable in the
// state it is seen in. The call here is bound to a local rather than written as a
// bare statement, which is the shape that put it in the look-ahead's path.
//
// The stub's class declaration is outside the analysed unit, so the interface
// token comparison is present but not accepted -- that is what makes this call
// site a relay and causes the handler body to be read ahead at all.
#include "common_types.h"

class IElsewhere {
public:
    static const char *GetDescriptor();
};

bool RelayLookaheadDeclarationStub::Allowed() const {
    return AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), "ohos.permission.MANAGE") == 0;
}

void RelayLookaheadDeclarationStub::HandleInner(MessageParcel &data, MessageParcel &reply) {
    if (!Allowed()) {
        reply.WriteInt32(-1);
        return;
    }
    int state = GetCallState();
    reply.WriteInt32(state);
}

int RelayLookaheadDeclarationStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IElsewhere::GetDescriptor()) return -1;
    switch (code) {
    case 1:
        HandleInner(data, reply);
        break;
    }
    return 0;
}
