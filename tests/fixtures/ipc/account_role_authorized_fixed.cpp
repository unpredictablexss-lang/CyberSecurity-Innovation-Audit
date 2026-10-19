// Engine control: only an explicit synthetic fixture policy accepts UID 3020.
// The default product policy does not establish account ownership or authority
// from this constant. This fixture is clean under fixture_account_policy(), and
// remains a candidate under the default policy. Preserve the following line
// count so the source-binding tests continue to cite the actual definition.
// No account assignment or product vulnerability is established by this file.
//
//
#include "common_types.h"

static const int32_t ACCESSTOKEN_UID = 3020;

class IFixtureAccountCallback {
public:
    static const char *GetDescriptor();
};

class AccountRoleStub : public IRemoteStub<IFixtureAccountCallback> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void GetRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply);
    void DeleteRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply);
    void UpdateRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply);
    bool IsAccessTokenCalling() const;
};

bool AccountRoleStub::IsAccessTokenCalling() const {
    int callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ACCESSTOKEN_UID;
}

void AccountRoleStub::GetRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply) {
    if (!IsAccessTokenCalling()) {
        reply.WriteInt32(-1);
        return;
    }
    int result = this->GetRemoteHapTokenInfo(1, 2);
    reply.WriteInt32(result);
}

void AccountRoleStub::DeleteRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply) {
    if (!IsAccessTokenCalling()) {
        reply.WriteInt32(-1);
        return;
    }
    int result = this->DeleteRemoteHapTokenInfo(1);
    reply.WriteInt32(result);
}

void AccountRoleStub::UpdateRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply) {
    if (!IsAccessTokenCalling()) {
        reply.WriteInt32(-1);
        return;
    }
    int result = this->UpdateRemoteHapTokenInfo(1);
    reply.WriteInt32(result);
}

int AccountRoleStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFixtureAccountCallback::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        GetRemoteHapTokenInfoInner(data, reply);
        break;
    case 2:
        DeleteRemoteHapTokenInfoInner(data, reply);
        break;
    case 3:
        UpdateRemoteHapTokenInfoInner(data, reply);
        break;
    }
    return 0;
}
