#define Stub Fixture_coverage_late_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
StartAbility(); if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), "ohos.permission.TEST") != PERMISSION_GRANTED) return -1;

return 0;
}
