#define Stub Fixture_position_underflow_safe
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
int32_t pos = data.ReadInt32();
int32_t remaining = data.GetDataSize() - pos;
if (remaining < 0) return -1;
data.ReadBuffer(remaining);
return 0;
}
