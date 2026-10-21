// Safe-shape control for D36: values are updated while holding the same lock
// used by snapshot-and-clear; no iterator/reference escapes to a caller.
#include <cstdint>
#include <iostream>
#include <map>
#include <mutex>
#include <thread>

struct RadarStatisticInfo {
    uint64_t userStartFailCount = 0;
};

using Statistics = std::map<uint32_t, RadarStatisticInfo>;

static Statistics opStatistics;
static std::mutex mutexStats;

void UpdateUserStatistics(uint32_t userId)
{
    std::lock_guard<std::mutex> lock(mutexStats);
    auto it = opStatistics.find(userId);
    if (it == opStatistics.end()) {
        it = opStatistics.insert(std::make_pair(userId, RadarStatisticInfo{})).first;
    }
    it->second.userStartFailCount++;
}

void GetTempStatistics(Statistics &statistics)
{
    std::lock_guard<std::mutex> lock(mutexStats);
    statistics.insert(opStatistics.begin(), opStatistics.end());
    opStatistics.clear();
}

int main()
{
    Statistics snapshot;
    std::thread radar([&] { GetTempStatistics(snapshot); });
    std::thread handler([&] { UpdateUserStatistics(100); });
    radar.join();
    handler.join();
    if (opStatistics.at(100).userStartFailCount != 1) {
        return 1;
    }
    std::cout << "safe control completed\n";
    return 0;
}
