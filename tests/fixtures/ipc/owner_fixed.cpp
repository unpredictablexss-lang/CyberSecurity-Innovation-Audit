#define Stub Fixture_owner_fixed
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), "ohos.permission.TEST") != PERMISSION_GRANTED) return -1;
int target=data.ReadInt32(); if (IPCSkeleton::GetCallingUid()!=GetOwnerUid(target)) return -1; DeleteUserData(target);
return 0;
}
