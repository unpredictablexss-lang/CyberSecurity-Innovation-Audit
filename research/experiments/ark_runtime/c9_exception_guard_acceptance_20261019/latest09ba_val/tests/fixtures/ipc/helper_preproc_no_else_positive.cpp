// M3 no-else control: the helper's only return is inside a conditional arm and the
// chain has no #else, so when the condition is not defined the function falls off
// its end without returning. The variant is unknown, so that path is kept, and a
// helper that does not always return cannot establish that its true branch was
// taken. The handler stays a candidate.
#include "common_types.h"

constexpr int ROOT_UID = 0;

class IFixturePreprocNoElse {
public:
    static const char *GetDescriptor();
};

class PreprocNoElseStub : public IRemoteStub<IFixturePreprocNoElse> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void HandleInner(MessageParcel &data, MessageParcel &reply);
    bool IsRootCalling() const;
};

bool PreprocNoElseStub::IsRootCalling() const {
#ifndef FIXTURE_USER_ENABLE
    int callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ROOT_UID;
#endif
}

void PreprocNoElseStub::HandleInner(MessageParcel &data, MessageParcel &reply) {
    if (!IsRootCalling()) {
        reply.WriteInt32(-1);
        return;
    }
    int result = GetRemoteHapTokenInfo(1, 2);
    reply.WriteInt32(result);
}

int PreprocNoElseStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFixturePreprocNoElse::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        HandleInner(data, reply);
        break;
    }
    return 0;
}
