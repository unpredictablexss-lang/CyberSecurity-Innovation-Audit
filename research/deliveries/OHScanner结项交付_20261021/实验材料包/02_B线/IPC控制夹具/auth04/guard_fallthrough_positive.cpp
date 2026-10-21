#define Stub Fixture_guard_fallthrough_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), "ohos.permission.TEST") != PERMISSION_GRANTED) { LOG("denied"); }
DeleteUserData(IPCSkeleton::GetCallingUid());
return 0;
}
