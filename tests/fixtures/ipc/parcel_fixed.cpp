#define Stub Fixture_parcel_fixed
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
char dst[64]; int n=data.ReadInt32(); if(n<0 || n>sizeof(dst)) return -1; memcpy(dst,data.ReadBuffer(64),n);
return 0;
}
