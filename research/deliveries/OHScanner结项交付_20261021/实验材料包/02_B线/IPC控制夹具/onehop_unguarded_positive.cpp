// M6 control: same shape as onehop_guard_fixed, and the implementer the handler
// dispatches to asks nothing about the caller at all. Producing the remote object
// and handing it to the stub is the whole body, so the export stands whatever the
// hop resolves to.
#include "common_types.h"

typedef RemoteObject *RemoteObjectPtr;

class OneHopUnguardedStub : public IPCObjectStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int HandleGetUIContent(MessageParcel &data, MessageParcel &reply);
    virtual int GetUIContent(int32_t persistentId, RemoteObjectPtr &object);
};

class OneHopUnguardedService : public OneHopUnguardedStub {
public:
    int GetUIContent(int32_t persistentId, RemoteObjectPtr &object) override;
};

int OneHopUnguardedStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
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

int OneHopUnguardedStub::HandleGetUIContent(MessageParcel &data, MessageParcel &reply) {
    int32_t persistentId = data.ReadInt32();
    RemoteObjectPtr object;
    GetUIContent(persistentId, object);
    reply.WriteRemoteObject(object);
    return 0;
}

int OneHopUnguardedService::GetUIContent(int32_t persistentId, RemoteObjectPtr &object) {
    object = PrivilegedObject();
    return 0;
}
