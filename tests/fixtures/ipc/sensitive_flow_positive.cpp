#define Stub Fixture_sensitive_flow_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
auto blob=ReadUserData(IPCSkeleton::GetCallingUid());
reply.WriteString(blob);
return 0;
}
