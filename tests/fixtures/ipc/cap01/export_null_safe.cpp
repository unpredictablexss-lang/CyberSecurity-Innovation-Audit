#define Stub Fixture_export_null_safe
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
reply.WriteRemoteObject(nullptr);
return 0;
}
