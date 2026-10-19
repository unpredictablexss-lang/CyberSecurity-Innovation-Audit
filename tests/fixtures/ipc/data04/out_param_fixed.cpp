#include <string>
class AppMgrStub {
public:
    virtual int GetBundleNameByPid(int pid, std::string &bundleName, int &uid);
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply) {
        if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
        int pid = data.ReadInt32();
        std::string bundleName;
        int uid = -1;
        int result = GetBundleNameByPid(pid, bundleName, uid);
        if (result != 0) return result;
        reply.WriteString(bundleName);
        reply.WriteInt32(uid);
        return 0;
    }
};
class AppMgrService : public AppMgrStub {
public:
    int GetBundleNameByPid(int pid, std::string &bundleName, int &uid) override {
        if (!IsSACall()) return -1;
        bundleName = LookupBundle(pid);
        uid = LookupUid(pid);
        return 0;
    }
};
