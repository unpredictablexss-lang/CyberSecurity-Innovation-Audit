#include <cstdint>
#include <cstdio>
#include <cstdlib>

struct FakeRemoteObject {
    bool IsProxyObject() const { return true; }
};

struct Parcel {
    explicit Parcel(int32_t count, size_t remaining)
        : count_(count), remaining_(remaining) {}

    int32_t ReadInt32() { return count_; }
    size_t Remaining() const { return remaining_; }
    FakeRemoteObject* ReadRemoteObject() { return &object_; }

private:
    int32_t count_;
    size_t remaining_;
    FakeRemoteObject object_;
};

static int64_t CJ_rpc_CreateRemoteObject(FakeRemoteObject*)
{
    return 0x12345678LL;
}

struct RemoteObjectArray {
    int32_t* type;
    int64_t* id;
    uint32_t len;
};

static bool CheckReadLength(const Parcel& parcel, size_t arrayLength, size_t typeSize)
{
    const size_t remainSize = parcel.Remaining();
    return !((arrayLength > remainSize) || (arrayLength * typeSize > remainSize));
}

// Isolated semantic harness for the pinned CJ_ReadRemoteObjectArray source:
// Parcel and remote-object values are deterministic stubs; allocation and
// indexed-store expressions are selected from the vulnerable/fixed revisions.
static RemoteObjectArray ReadRemoteObjectArray(Parcel& parcel, int32_t* errCode)
{
    RemoteObjectArray res{nullptr, nullptr, 0};
    int32_t arrayLength = parcel.ReadInt32();
    if (arrayLength <= 0) {
        return res;
    }
    if (CheckReadLength(parcel, static_cast<size_t>(arrayLength), 4)) {
#ifdef REPRO_VULNERABLE
        int32_t* type = static_cast<int32_t*>(malloc(arrayLength));
        int64_t* id = static_cast<int64_t*>(malloc(arrayLength));
#else
        int32_t* type = static_cast<int32_t*>(malloc(sizeof(int32_t) * arrayLength));
        int64_t* id = static_cast<int64_t*>(malloc(sizeof(int64_t) * arrayLength));
#endif
        if (type == nullptr || id == nullptr) {
            free(type);
            free(id);
            *errCode = -1;
            return res;
        }
        for (uint32_t i = 0; i < static_cast<uint32_t>(arrayLength); i++) {
            FakeRemoteObject* value = parcel.ReadRemoteObject();
#ifndef REPRO_VULNERABLE
            if (value == nullptr) {
                type[i] = -1;
                id[i] = -1;
                continue;
            }
#endif
            type[i] = value->IsProxyObject() ? 1 : 0;
            id[i] = CJ_rpc_CreateRemoteObject(value);
        }
#ifndef REPRO_VULNERABLE
        res.len = static_cast<uint32_t>(arrayLength);
#endif
        res.type = type;
        res.id = id;
        free(type);
        free(id);
        return res;
    }
    *errCode = -1;
    return res;
}

int main(int argc, char** argv)
{
    const int32_t count = argc > 1 ? static_cast<int32_t>(std::strtol(argv[1], nullptr, 10)) : 4;
    const size_t remaining = argc > 2
        ? static_cast<size_t>(std::strtoul(argv[2], nullptr, 10))
        : static_cast<size_t>(count) * 4;
    Parcel parcel(count, remaining);
    int32_t error = 0;
    const RemoteObjectArray result = ReadRemoteObjectArray(parcel, &error);
    std::printf("count=%d len=%u error=%d\n", count, result.len, error);
    return error == 0 ? 0 : 2;
}
