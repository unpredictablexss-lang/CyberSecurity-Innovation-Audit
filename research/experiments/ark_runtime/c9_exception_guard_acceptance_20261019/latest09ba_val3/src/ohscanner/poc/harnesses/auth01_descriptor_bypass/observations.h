// Records what the service actually did, so the harness can report it.
#ifndef POC_OBSERVATIONS_H
#define POC_OBSERVATIONS_H

#include <cstdint>
#include <vector>

namespace poc {
struct SentMessage {
    int32_t msgId;
    size_t contentBytes;
    int32_t userId;
    int32_t contentCount;
};

inline std::vector<SentMessage> &sent()
{
    static std::vector<SentMessage> records;
    return records;
}
} // namespace poc

#endif
