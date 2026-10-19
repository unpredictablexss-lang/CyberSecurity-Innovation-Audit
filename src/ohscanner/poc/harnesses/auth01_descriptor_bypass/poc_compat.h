// Harness compatibility shim, forced in with -include.
//
// Why it exists: at the vulnerable commit the inputmethod_imf headers declare
// `ErrorCode` as a namespace holding an unscoped enum, and
// platform_callback_stub.cpp writes `return NO_ERROR;` unqualified. The name is
// not reachable from the enclosing namespace by C++ lookup, and no using
// directive exists in the historical header set -- so the translation unit does
// not compile in isolation against its own headers.
//
// This shim supplies exactly that using directive for the harness build. It does
// not touch the component source, and it does not change any behaviour: the
// symbol it makes visible is the one the code already names.
#ifndef POC_COMPAT_H
#define POC_COMPAT_H

#include "global.h"

namespace OHOS {
namespace MiscServices {
using namespace ErrorCode;
} // namespace MiscServices
} // namespace OHOS

#endif
