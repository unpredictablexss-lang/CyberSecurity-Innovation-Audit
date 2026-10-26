#define Stub Fixture_position_underflow_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
int32_t pos = data.ReadInt32();
data.RewindRead(data.GetDataSize() - pos);
return 0;
}
