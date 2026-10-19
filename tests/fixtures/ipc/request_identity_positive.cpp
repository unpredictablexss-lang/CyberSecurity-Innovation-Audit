#define Stub Fixture_request_identity_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
auto token=data.ReadUint32(); if (AccessTokenKit::VerifyAccessToken(token,"p") != 0) return -1; StartAbility();
return 0;
}
