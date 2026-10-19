#define Stub Fixture_switch_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
switch(code){ case 1: if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), "ohos.permission.TEST") != PERMISSION_GRANTED) return -1;
 StartAbility(); break; case 2: StartAbility(); break; default: return -1;}
return 0;
}
