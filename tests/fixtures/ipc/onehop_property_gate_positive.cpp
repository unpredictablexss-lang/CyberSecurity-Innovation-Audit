// M6 control: the implementer opens with a check, but the question it asks is
// about the request -- whether this session property may be recovered -- not about
// who is calling. A property question is not a caller-role gate, so the export
// stays a candidate. This is the shape that keeps a permission-shaped helper from
// being read as caller authorization: the gate has to answer about the caller.
#include "common_types.h"

typedef RemoteObject *RemoteObjectPtr;

class OneHopPropertyGateStub : public IPCObjectStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int HandleGetUIContent(MessageParcel &data, MessageParcel &reply);
    virtual int GetUIContent(int32_t persistentId, RemoteObjectPtr &object);
};

class OneHopPropertyGateService : public OneHopPropertyGateStub {
public:
    int GetUIContent(int32_t persistentId, RemoteObjectPtr &object) override;
};

int OneHopPropertyGateStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
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

int OneHopPropertyGateStub::HandleGetUIContent(MessageParcel &data, MessageParcel &reply) {
    int32_t persistentId = data.ReadInt32();
    RemoteObjectPtr object;
    GetUIContent(persistentId, object);
    reply.WriteRemoteObject(object);
    return 0;
}

int OneHopPropertyGateService::GetUIContent(int32_t persistentId, RemoteObjectPtr &object) {
    if (!CheckSessionPropertyOnRecovery(persistentId)) {
        return -1;
    }
    object = PrivilegedObject();
    return 0;
}
