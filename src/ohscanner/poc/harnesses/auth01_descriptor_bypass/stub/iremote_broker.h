// Minimal stand-in for the ipc_core public header of the same name.
//
// DECLARE_INTERFACE_DESCRIPTOR is copied verbatim from the real header, because
// it is what supplies GetDescriptor() to the interface class under test.
#ifndef STUB_IREMOTE_BROKER_H
#define STUB_IREMOTE_BROKER_H

#include <string>

#include "refbase.h"

namespace OHOS {
class IRemoteObject;

class IRemoteBroker {
public:
    IRemoteBroker() = default;
    virtual ~IRemoteBroker() = default;
    // The real class also declares AsObject(); it is omitted here because
    // nothing in the exercised path calls it and instantiating sptr<IRemoteObject>
    // would require the real IRemoteObject definition.
};
} // namespace OHOS

#define DECLARE_INTERFACE_DESCRIPTOR(DESCRIPTOR)                         \
    static constexpr const char16_t *metaDescriptor_ = DESCRIPTOR;       \
    static inline const std::u16string GetDescriptor()                  \
    {                                                                    \
        return metaDescriptor_;                                          \
    }

#endif
