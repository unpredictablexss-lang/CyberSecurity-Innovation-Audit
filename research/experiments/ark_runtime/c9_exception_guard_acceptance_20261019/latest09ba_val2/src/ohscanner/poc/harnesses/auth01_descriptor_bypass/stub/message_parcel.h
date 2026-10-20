// Thin shim over the REAL c_utils Parcel.
//
// Only the two interface-token methods are added, with the same semantics the
// ipc_core implementation has: writing the token appends it as a string16, and
// reading it back returns the string16 that was written. Everything the
// component calls besides those two (ReadInt32, ReadString16, WriteInt32, ...)
// is the real Parcel implementation.
#ifndef STUB_MESSAGE_PARCEL_H
#define STUB_MESSAGE_PARCEL_H

#include <string>

#include "parcel.h"

namespace OHOS {
class MessageParcel : public Parcel {
public:
    MessageParcel() = default;
    ~MessageParcel() override = default;

    bool WriteInterfaceToken(const std::u16string &token)
    {
        descriptor_ = token;
        return WriteString16(token);
    }

    std::u16string ReadInterfaceToken()
    {
        return ReadString16();
    }

    const std::u16string &GetInterfaceToken() const
    {
        return descriptor_;
    }

private:
    std::u16string descriptor_;
};
} // namespace OHOS

#endif
