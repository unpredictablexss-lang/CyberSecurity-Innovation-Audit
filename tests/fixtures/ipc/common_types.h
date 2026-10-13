#pragma once
#include <cstdint>
#include <cstring>
#include <string>
struct MessageOption {};
struct RemoteObject {};
struct MessageParcel {
 std::u16string ReadInterfaceToken(); int ReadInt32(); unsigned ReadUint32();
 const char *ReadBuffer(unsigned); RemoteObject *ReadRemoteObject();
 bool WriteRemoteObject(RemoteObject *); bool WriteFileDescriptor(int);
};
struct IPCSkeleton { static unsigned GetCallingTokenID(); static int GetCallingUid(); static std::string ResetCallingIdentity(); static bool SetCallingIdentity(const std::string&); };
struct AccessTokenKit { static int VerifyAccessToken(unsigned,const char *); };
constexpr int PERMISSION_GRANTED=0; constexpr int PERMISSION_DENIED=-1;
std::u16string GetDescriptor(); unsigned GetSelfTokenID(); int getuid();
void StartAbility(); void OnCallback(); void DeleteUserData(int); int GetOwnerUid(int);
RemoteObject *PrivilegedObject(); void LOG(const char *);
struct Stub { int OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option); bool Allowed(); void Handle(MessageParcel &data); };
