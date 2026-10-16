// The reviewed account, resolved from the source. `ITokenSyncCallback` exists for
// one caller -- the access-token service -- so a handler of that interface that
// admits only the calling UID the source binds `ACCESSTOKEN_UID` to is authorized,
// and the three operations the model names are the ones this guard decides. The
// credential is the *definition*, not the spelling of the name: the constant below
// resolves to 3020 in this file, and the model's record for the access-token
// service is 3020. Nothing else about this stub is credited -- the account is not
// a permission and not a general caller role.
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
