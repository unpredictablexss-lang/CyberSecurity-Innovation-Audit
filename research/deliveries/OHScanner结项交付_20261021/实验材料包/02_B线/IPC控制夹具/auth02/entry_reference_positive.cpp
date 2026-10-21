#define Stub Fixture_entry_reference_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
DeleteUserData(IPCSkeleton::GetCallingUid());
return 0;
}
