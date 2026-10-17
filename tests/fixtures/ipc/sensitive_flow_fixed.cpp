#define Stub Fixture_sensitive_flow_fixed
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), "ohos.permission.READ_USER_DATA") != PERMISSION_GRANTED) return -1;
auto blob=ReadUserData(IPCSkeleton::GetCallingUid());
reply.WriteString(blob);
return 0;
}
