// MessageParcel shim over the REAL c_utils Parcel.
//
// Only descriptor transfer is supplied here, because that is the piece the
// component touches and the piece that has no standalone c_utils equivalent:
// ipc_core implements it with a binder object (IPCFileDescriptor), which needs
// the binder driver. The semantics that matter for the question are preserved:
// what the reader receives is a descriptor of the same underlying file as the
// one the writer passed in, and the reader's mmap() acts on that file.
//
// Every other method used by the component (ReadInt64, ReadUnpadBuffer,
// WriteInt32, ReadInt32, ...) is the real Parcel implementation from the
// pinned c_utils sources.
#ifndef STUB_MESSAGE_PARCEL_H
#define STUB_MESSAGE_PARCEL_H

#include <unistd.h>

#include <memory>

#include "parcel.h"

namespace OHOS {
class MessageParcel : public Parcel {
public:
    bool WriteFileDescriptor(int fd)
    {
        if (fd < 0) {
            return false;
        }
        int copy = dup(fd);
        if (copy < 0) {
            return false;
        }
        if (!WriteInt32(copy)) {
            close(copy);
            return false;
        }
        return true;
    }

    int ReadFileDescriptor()
    {
        int32_t fd = ReadInt32();
        if (fd < 0) {
            return -1;
        }
        // A fresh descriptor for the same open file description: the reader
        // cannot influence the writer's descriptor lifetime, matching the
        // duplicating behaviour of the ipc_core implementation.
        return dup(fd);
    }
};
} // namespace OHOS

#endif
