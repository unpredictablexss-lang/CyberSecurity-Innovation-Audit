#define Stub Fixture_relay_read_only_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
data.ReadInterfaceToken(); OnCallback();
return 0;
}
