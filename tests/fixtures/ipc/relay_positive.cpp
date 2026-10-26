#define Stub Fixture_relay_positive
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
OnCallback();
return 0;
}
