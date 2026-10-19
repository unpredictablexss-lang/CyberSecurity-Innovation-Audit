#define Stub Fixture_auth_ignored_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), "p"); StartAbility();
return 0;
}
