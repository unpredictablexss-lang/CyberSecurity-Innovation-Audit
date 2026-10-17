// Minimal stand-in for the OpenHarmony init/syspara parameters header.
//
// The component calls OHOS::system::GetIntParameter(key, def) once, in the
// MessageParcelWarp constructor, to size its maximum raw payload. There is no
// parameter service in the harness, so the documented default is returned; the
// value is 128 MiB, far above every size exercised here, so this choice does
// not decide any outcome.
#ifndef STUB_PARAMETERS_H
#define STUB_PARAMETERS_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace system {
inline int32_t GetIntParameter(const std::string &, int32_t def)
{
    return def;
}
} // namespace system
} // namespace OHOS

#endif
