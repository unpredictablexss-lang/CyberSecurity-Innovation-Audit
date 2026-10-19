#define Stub Fixture_onehop_ungated_positive
#include "common_types.h"

typedef RemoteObject *RemoteObjectPtr;

class FixtureOnehopStub {
public:
int OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option);
int HandleGetObject(MessageParcel &data,MessageParcel &reply);
virtual int GetObject(int32_t id,RemoteObjectPtr &object);
};

class FixtureOnehopService : public FixtureOnehopStub {
public:
int GetObject(int32_t id,RemoteObjectPtr &object) override;
};

int FixtureOnehopStub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (code == 1) return HandleGetObject(data,reply);
return 0;
}

int FixtureOnehopStub::HandleGetObject(MessageParcel &data,MessageParcel &reply) {
int32_t id = data.ReadInt32();
RemoteObjectPtr object;
GetObject(id,object);
reply.WriteRemoteObject(object);
return 0;
}

int FixtureOnehopService::GetObject(int32_t id,RemoteObjectPtr &object) {
object = PrivilegedObject();
return 0;
}
