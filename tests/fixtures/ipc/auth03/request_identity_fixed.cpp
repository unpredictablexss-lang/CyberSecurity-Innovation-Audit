#define Stub Fixture_request_identity_fixed
#include "../common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), "p") != 0) return -1; StartAbility();
return 0;
}
