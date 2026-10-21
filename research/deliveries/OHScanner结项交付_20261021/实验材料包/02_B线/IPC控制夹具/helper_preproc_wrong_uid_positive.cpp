// M3 wrong-identity control: the helper does read the real caller uid, but it
// compares against a peer that is not a trusted identity. Reading the caller is
// not the same as establishing that the caller is allowed.
#include "common_types.h"

constexpr int PEER_UID = 1001;

class IFixturePreprocWrongUid {
public:
    static const char *GetDescriptor();
};

class PreprocWrongUidStub : public IRemoteStub<IFixturePreprocWrongUid> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void HandleInner(MessageParcel &data, MessageParcel &reply);
    bool IsPeerCalling() const;
};

bool PreprocWrongUidStub::IsPeerCalling() const {
#ifndef FIXTURE_USER_ENABLE
    int callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == PEER_UID;
#else
    return false;
#endif
}

void PreprocWrongUidStub::HandleInner(MessageParcel &data, MessageParcel &reply) {
    if (!IsPeerCalling()) {
        reply.WriteInt32(-1);
        return;
    }
    int result = GetRemoteHapTokenInfo(1, 2);
    reply.WriteInt32(result);
}

int PreprocWrongUidStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFixturePreprocWrongUid::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        HandleInner(data, reply);
        break;
    }
    return 0;
}
