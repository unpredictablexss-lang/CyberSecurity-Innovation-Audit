// Minimal stand-in for the ipc_core public header of the same name.
#ifndef STUB_IPC_TYPES_H
#define STUB_IPC_TYPES_H

#include <cstdint>

namespace OHOS {
using ErrCode = int;
constexpr uint32_t FIRST_CALL_TRANSACTION = 0x00000001;
constexpr uint32_t LAST_CALL_TRANSACTION = 0x00ffffff;
} // namespace OHOS

#endif
