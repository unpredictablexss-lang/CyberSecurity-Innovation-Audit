#define Stub Fixture_data02_write_bounds_safe
#include "../common_types.h"

int Stub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                          MessageOption &option) {
    if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
    char destination[64];
    data.ReadRawData(destination, sizeof(destination));
    return 0;
}
