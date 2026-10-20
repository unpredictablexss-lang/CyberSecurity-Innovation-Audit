#define Stub Fixture_helper_positive
#include "common_types.h"
void Stub::Handle(MessageParcel &data){ StartAbility(); }
int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
Handle(data);
return 0;
}
