#define Stub Fixture_data04_positive
#include "common_types.h"
int Stub::OnRemoteRequest(uint32_t code, MessageParcel &data,
                          MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
    bool running = GetAppRunningStateByBundleName(data.ReadString());
    reply.WriteBool(running);
    return 0;
}
