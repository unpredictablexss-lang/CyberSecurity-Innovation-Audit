// M6 cross-TU one hop: the stub does not define the method its handler calls.
// The concrete service derives from OneHopGuardStub and rejects every caller that
// is not a system-ability caller before it produces the remote object the stub
// then writes into the reply. The call site in the stub is therefore not an
// export to an unauthorized caller, and reading one class hop into the
// implementer is what shows that. The implementer's body is written inside its
// class, as most of these bodies are, so this also pins the provenance line
// naming `OneHopGuardService::GetUIContent` rather than a bare method name.
#include "common_types.h"

typedef RemoteObject *RemoteObjectPtr;

class OneHopGuardStub : public IPCObjectStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int HandleGetUIContent(MessageParcel &data, MessageParcel &reply);
    virtual int GetUIContent(int32_t persistentId, RemoteObjectPtr &object);
};

class OneHopGuardService : public OneHopGuardStub {
public:
    int GetUIContent(int32_t persistentId, RemoteObjectPtr &object) override {
        if (!IsSACalling()) {
            return -1;
        }
        object = PrivilegedObject();
        return 0;
    }
};

int OneHopGuardStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
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

int OneHopGuardStub::HandleGetUIContent(MessageParcel &data, MessageParcel &reply) {
    int32_t persistentId = data.ReadInt32();
    RemoteObjectPtr object;
    GetUIContent(persistentId, object);
    reply.WriteRemoteObject(object);
    return 0;
}
