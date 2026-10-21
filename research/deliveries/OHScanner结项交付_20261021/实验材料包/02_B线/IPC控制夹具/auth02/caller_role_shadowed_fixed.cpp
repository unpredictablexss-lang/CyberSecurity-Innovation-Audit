#define Stub Fixture_caller_role_shadowed_fixed
#include "common_types.h"

constexpr int SERVICE_UID = 4096;

class Stub {
public:
int OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option);
bool IsAccessTokenCalling() const;
};

bool Stub::IsAccessTokenCalling() const {
int callingUid = IPCSkeleton::GetCallingUid();
return callingUid == 0;
}

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (!IsAccessTokenCalling()) return -1;
DeleteUserData(IPCSkeleton::GetCallingUid());
return 0;
}
