#define Stub Fixture_identity_domain_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingUid(), "ohos.permission.TEST") != PERMISSION_GRANTED) return -1;
StartAbility();
return 0;
}
