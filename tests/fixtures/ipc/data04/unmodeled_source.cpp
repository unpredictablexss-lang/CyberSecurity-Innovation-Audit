#define Stub Fixture_data04_unknown_source
#include "common_types.h"
int Stub::OnRemoteRequest(uint32_t code, MessageParcel &data,
                          MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
    bool value = GetUnmodeledRuntimeState(data.ReadString());
    reply.WriteBool(value);
    return 0;
}
