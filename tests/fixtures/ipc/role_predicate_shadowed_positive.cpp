// M6: the reviewed caller-role names are credited where the scanned sources do
// not define the name themselves. Here they do. `IsAccessTokenCalling` is a
// reviewed predicate -- a true answer means the caller holds the service role --
// and this translation unit writes its own definition of that name, which answers
// with a UID the reviewed set carries no role for. A local function of the same
// name is a different function, so the reviewed fact does not travel to it and
// the operation stays a candidate. The run says which body took the name's place,
// so that candidate reads as "this body has to be reviewed", not as "no guard was
// written". `helper_preproc_guard_fixed` is the other half of the pair: there the
// same-file body does carry a reviewed fact and the operation is suppressed.
#include "common_types.h"

constexpr int SERVICE_UID = 4096;

class IFixtureShadowedRole {
public:
    static const char *GetDescriptor();
};

class ShadowedRoleStub : public IRemoteStub<IFixtureShadowedRole> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void HandleInner(MessageParcel &data, MessageParcel &reply);
    bool IsAccessTokenCalling() const;
};

bool ShadowedRoleStub::IsAccessTokenCalling() const {
    int callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == SERVICE_UID;
}

void ShadowedRoleStub::HandleInner(MessageParcel &data, MessageParcel &reply) {
    if (!IsAccessTokenCalling()) {
        reply.WriteInt32(-1);
        return;
    }
    int result = GetRemoteHapTokenInfo(1, 2);
    reply.WriteInt32(result);
}

int ShadowedRoleStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFixtureShadowedRole::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        HandleInner(data, reply);
        break;
    }
    return 0;
}
