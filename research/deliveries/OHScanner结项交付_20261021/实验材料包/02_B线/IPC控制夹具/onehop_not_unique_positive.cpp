// M6 control: two classes derive from the stub and both define the method the
// handler calls, so the one hop is not unique. Which body runs depends on the
// object the caller reached, which the sources here do not settle. An unresolved
// hop is reported as not established -- never as "the implementer guards" -- and
// the export stays a candidate. Both implementers do gate here; the point is that
// the analysis cannot use either as the answer.
#include "common_types.h"

typedef RemoteObject *RemoteObjectPtr;

class OneHopNotUniqueStub : public IPCObjectStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int HandleGetUIContent(MessageParcel &data, MessageParcel &reply);
    virtual int GetUIContent(int32_t persistentId, RemoteObjectPtr &object);
};

class OneHopNotUniqueServiceA : public OneHopNotUniqueStub {
public:
    int GetUIContent(int32_t persistentId, RemoteObjectPtr &object) override;
};

class OneHopNotUniqueServiceB : public OneHopNotUniqueStub {
public:
    int GetUIContent(int32_t persistentId, RemoteObjectPtr &object) override;
};

int OneHopNotUniqueStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
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

int OneHopNotUniqueStub::HandleGetUIContent(MessageParcel &data, MessageParcel &reply) {
    int32_t persistentId = data.ReadInt32();
    RemoteObjectPtr object;
    GetUIContent(persistentId, object);
    reply.WriteRemoteObject(object);
    return 0;
}

int OneHopNotUniqueServiceA::GetUIContent(int32_t persistentId, RemoteObjectPtr &object) {
    if (!IsSACalling()) {
        return -1;
    }
    object = PrivilegedObject();
    return 0;
}

int OneHopNotUniqueServiceB::GetUIContent(int32_t persistentId, RemoteObjectPtr &object) {
    if (!IsSACalling()) {
        return -1;
    }
    object = PrivilegedObject();
    return 0;
}
