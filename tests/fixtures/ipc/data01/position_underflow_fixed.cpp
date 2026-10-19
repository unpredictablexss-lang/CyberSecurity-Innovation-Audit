#define Stub Fixture_position_underflow_fixed
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
int32_t pos = data.ReadInt32();
if (pos < 0 || data.GetDataSize() < pos) return -1;
data.RewindRead(data.GetDataSize() - pos);
return 0;
}
