#define Stub Fixture_auth03_request_identity_safe
#include "../common_types.h"

int Stub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                          MessageOption &option) {
    if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
    uint32_t requestedToken = data.ReadUint32();
    if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(),
                                          "ohos.permission.TEST") != PERMISSION_GRANTED) return -1;
    AccessTokenKit::GetTokenType(requestedToken);
    return 0;
}
