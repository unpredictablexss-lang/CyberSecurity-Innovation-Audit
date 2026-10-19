// M3 substituted-parameter control: the helper is a correct trusted-uid test, but
// the handler hands it a value read from the request instead of the caller. The
// helper's own reading of the caller is what makes it a guard; without that, its
// answer says nothing about who is calling.
#include "common_types.h"

constexpr int ROOT_UID = 0;

class IFixturePreprocParam {
public:
    static const char *GetDescriptor();
};

class PreprocParamStub : public IRemoteStub<IFixturePreprocParam> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void HandleInner(MessageParcel &data, MessageParcel &reply);
    bool IsTrustedUid(int uid) const;
};

bool PreprocParamStub::IsTrustedUid(int uid) const {
#ifndef FIXTURE_USER_ENABLE
    return uid == ROOT_UID;
#else
    return false;
#endif
}

void PreprocParamStub::HandleInner(MessageParcel &data, MessageParcel &reply) {
    if (!IsTrustedUid(data.ReadInt32())) {
        reply.WriteInt32(-1);
        return;
    }
    int result = GetRemoteHapTokenInfo(1, 2);
    reply.WriteInt32(result);
}

int PreprocParamStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFixturePreprocParam::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        HandleInner(data, reply);
        break;
    }
    return 0;
}
