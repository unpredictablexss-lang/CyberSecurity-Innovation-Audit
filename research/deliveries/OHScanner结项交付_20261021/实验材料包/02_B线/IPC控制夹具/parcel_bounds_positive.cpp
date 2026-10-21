#define Stub Fixture_parcel_bounds_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
char dst[64]; int n=data.ReadInt32();
dst[n]=0;
return 0;
}
