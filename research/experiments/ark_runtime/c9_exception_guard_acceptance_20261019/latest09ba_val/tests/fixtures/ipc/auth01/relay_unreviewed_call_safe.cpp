#define Stub Fixture_relay_unreviewed_call_safe
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
int32_t op = data.ReadInt32();
UpdateStatistics(op);
return 0;
}
