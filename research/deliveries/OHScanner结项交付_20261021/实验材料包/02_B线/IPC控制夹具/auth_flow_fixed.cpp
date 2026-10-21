#define Stub Fixture_auth_flow_fixed
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), "ohos.permission.TEST") != PERMISSION_GRANTED) return -1;
auto saved=IPCSkeleton::ResetCallingIdentity();
IPCSkeleton::SetCallingIdentity(saved);
StartAbility();
return 0;
}
