#define Stub Fixture_data01_copy_range_safe
#include "../common_types.h"

int Stub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                          MessageOption &option) {
    if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
    char destination[64];
    const void *payload = data.ReadBuffer(sizeof(destination));
    memcpy(destination, payload, sizeof(destination));
    return 0;
}
