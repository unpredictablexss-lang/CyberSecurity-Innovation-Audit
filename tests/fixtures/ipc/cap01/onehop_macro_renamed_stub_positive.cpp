#define Stub Fixture_onehop_macro_renamed_stub_positive
#include "common_types.h"

typedef RemoteObject *RemoteObjectPtr;

class Stub {
public:
int OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option);
int HandleGetObject(MessageParcel &data,MessageParcel &reply);
virtual int GetObject(int32_t id,RemoteObjectPtr &object);
};

class FixtureOnehopService : public Stub {
public:
int GetObject(int32_t id,RemoteObjectPtr &object) override;
};

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (code == 1) return HandleGetObject(data,reply);
return 0;
}

int Stub::HandleGetObject(MessageParcel &data,MessageParcel &reply) {
int32_t id = data.ReadInt32();
RemoteObjectPtr object;
GetObject(id,object);
reply.WriteRemoteObject(object);
return 0;
}

int FixtureOnehopService::GetObject(int32_t id,RemoteObjectPtr &object) {
if (!IsSACalling()) return -1;
object = PrivilegedObject();
return 0;
}
