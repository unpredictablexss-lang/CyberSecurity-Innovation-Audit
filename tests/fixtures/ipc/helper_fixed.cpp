#define Stub Fixture_helper_fixed
#include "common_types.h"
bool Stub::Allowed(){ return AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), "p")==0; }
int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (!Allowed()) return -1; StartAbility();
return 0;
}
