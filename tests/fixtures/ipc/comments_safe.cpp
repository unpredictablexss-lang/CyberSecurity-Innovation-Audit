#define Stub Fixture_comments_safe
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
// StartAbility(); GetSelfTokenID();
LOG("StartAbility() CheckPermission()");
return 0;
}
