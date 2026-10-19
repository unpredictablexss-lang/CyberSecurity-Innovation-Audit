// M6 control: the implementer does check the caller, but only after it has
// already done something this analysis models -- `Dump()` here stands for any
// sensitive operation the callee performs before it asks who is calling. A gate
// covers what comes after it and nothing before it, so an unauthorized caller
// still reaches the modelled operation and the call site keeps its candidate.
#include "common_types.h"

typedef RemoteObject *RemoteObjectPtr;

class OneHopLateGateStub : public IPCObjectStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int HandleGetUIContent(MessageParcel &data, MessageParcel &reply);
    virtual int GetUIContent(int32_t persistentId, RemoteObjectPtr &object);
};

class OneHopLateGateService : public OneHopLateGateStub {
public:
    int GetUIContent(int32_t persistentId, RemoteObjectPtr &object) override;
};

int OneHopLateGateStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        return HandleGetUIContent(data, reply);
    default:
        break;
    }
    return 0;
}

int OneHopLateGateStub::HandleGetUIContent(MessageParcel &data, MessageParcel &reply) {
    int32_t persistentId = data.ReadInt32();
    RemoteObjectPtr object;
    GetUIContent(persistentId, object);
    reply.WriteRemoteObject(object);
    return 0;
}

int OneHopLateGateService::GetUIContent(int32_t persistentId, RemoteObjectPtr &object) {
    Dump();
    if (!IsSACalling()) {
        return -1;
    }
    object = PrivilegedObject();
    return 0;
}
