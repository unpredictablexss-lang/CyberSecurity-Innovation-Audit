// The same name, a different account. This file writes its own
// `ACCESSTOKEN_UID`, and it binds it to 4096 -- not the 3020 the reviewed account
// record names for the access-token service. The guard looks exactly like the one
// the model describes and admits a different principal, so nothing is derived from
// it: a name is not an identity, and the operation behind the guard stays a
// candidate. The run names the definition it read and the value it found, so this
// candidate reads as "a UID guard here answers 4096", not as "no guard was written".
#include "common_types.h"

static const int32_t ACCESSTOKEN_UID = 4096;

class IFixtureWrongValue {
public:
    static const char *GetDescriptor();
};

class WrongValueStub : public IRemoteStub<IFixtureWrongValue> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void GetRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply);
    bool IsAccessTokenCalling() const;
};

bool WrongValueStub::IsAccessTokenCalling() const {
    int callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ACCESSTOKEN_UID;
}

void WrongValueStub::GetRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply) {
    if (!IsAccessTokenCalling()) {
        reply.WriteInt32(-1);
        return;
    }
    int result = this->GetRemoteHapTokenInfo(1, 2);
    reply.WriteInt32(result);
}

int WrongValueStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFixtureWrongValue::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        GetRemoteHapTokenInfoInner(data, reply);
        break;
    }
    return 0;
}
