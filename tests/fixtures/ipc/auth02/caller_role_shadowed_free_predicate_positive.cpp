#define Stub Fixture_caller_role_shadowed_free_predicate_positive
#include "common_types.h"

constexpr int SERVICE_UID = 4096;

bool IsAccessTokenCalling() {
int callingUid = IPCSkeleton::GetCallingUid();
return callingUid == SERVICE_UID;
}

class Stub {
public:
int OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option);
};

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (!IsAccessTokenCalling()) return -1;
DeleteUserData(IPCSkeleton::GetCallingUid());
return 0;
}
