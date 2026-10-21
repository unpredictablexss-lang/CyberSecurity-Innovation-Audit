// The caller is not the request. `claimedUid` is read out of the parcel, so the
// comparison is between something the caller wrote and the reviewed account number
// -- and a caller that can write 3020 into its own request would satisfy it. The
// condition is a request-shape check, not a caller-identity check, and the model
// derives nothing from it: the operation stays a candidate. This is the
// caller-versus-request distinction the account role has to keep.
#include "common_types.h"

static const int32_t ACCESSTOKEN_UID = 3020;

class IFixtureRequestIdentity {
public:
    static const char *GetDescriptor();
};

class RequestIdentityStub : public IRemoteStub<IFixtureRequestIdentity> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void GetRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply);
};

void RequestIdentityStub::GetRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply) {
    uint32_t claimedUid = data.ReadUint32();
    if (claimedUid != ACCESSTOKEN_UID) {
        reply.WriteInt32(-1);
        return;
    }
    int result = this->GetRemoteHapTokenInfo(1, 2);
    reply.WriteInt32(result);
}

int RequestIdentityStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFixtureRequestIdentity::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        GetRemoteHapTokenInfoInner(data, reply);
        break;
    }
    return 0;
}
