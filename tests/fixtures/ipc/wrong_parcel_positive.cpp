#define Stub Fixture_wrong_parcel_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if(reply.ReadInterfaceToken()!=GetDescriptor()) return -1; OnCallback();
return 0;
}
