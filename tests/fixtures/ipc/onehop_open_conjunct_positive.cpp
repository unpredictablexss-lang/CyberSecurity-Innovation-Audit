// M6 control: the implementer's opening gate is a conjunction whose second
// conjunct this analysis cannot settle -- `!Permission::IsStartByHdcd()` is not a
// reviewed caller-role predicate and its definition is not in the shard. The
// caller therefore continues when it is a system-ability caller *or* when that
// conjunct is false, and the second branch is a caller the gate did not establish
// anything about. A gate that can be short-circuited past is not credited, so the
// export stays a candidate rather than being argued away by the first conjunct.
#include "common_types.h"

typedef RemoteObject *RemoteObjectPtr;

class OneHopOpenConjunctStub : public IPCObjectStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int HandleGetUIContent(MessageParcel &data, MessageParcel &reply);
    virtual int GetUIContent(int32_t persistentId, RemoteObjectPtr &object);
};

class OneHopOpenConjunctService : public OneHopOpenConjunctStub {
public:
    int GetUIContent(int32_t persistentId, RemoteObjectPtr &object) override;
};

int OneHopOpenConjunctStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
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

int OneHopOpenConjunctStub::HandleGetUIContent(MessageParcel &data, MessageParcel &reply) {
    int32_t persistentId = data.ReadInt32();
    RemoteObjectPtr object;
    GetUIContent(persistentId, object);
    reply.WriteRemoteObject(object);
    return 0;
}

int OneHopOpenConjunctService::GetUIContent(int32_t persistentId, RemoteObjectPtr &object) {
    if (!IsSACalling() && !Permission::IsStartByHdcd()) {
        return -1;
    }
    object = PrivilegedObject();
    return 0;
}
