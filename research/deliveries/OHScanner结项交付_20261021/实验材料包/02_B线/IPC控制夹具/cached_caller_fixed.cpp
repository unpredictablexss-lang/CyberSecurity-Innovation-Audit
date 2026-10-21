#define Stub Fixture_cached_caller_fixed
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
auto caller=IPCSkeleton::GetCallingTokenID(); auto saved=IPCSkeleton::ResetCallingIdentity(); if (AccessTokenKit::VerifyAccessToken(caller,"p")!=0) return -1; StartAbility();
return 0;
}
