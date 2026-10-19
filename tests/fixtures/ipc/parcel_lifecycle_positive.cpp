#define Stub Fixture_parcel_lifecycle_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
const char *view=data.ReadBuffer(32);
data.Reuse();
char first=view[0];
return first;
}
