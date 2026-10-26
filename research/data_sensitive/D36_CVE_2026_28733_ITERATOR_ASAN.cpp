// Source-shaped lifetime harness for CVE-2026-28733 review.
// This is a minimal model of the inspected StorageDaemonStub map/iterator
// sequence, not a build of the OpenHarmony service or a product exploit.
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <map>
#include <mutex>
#include <thread>

struct RadarStatisticInfo {
    uint64_t userStartFailCount = 0;
};

using Statistics = std::map<uint32_t, RadarStatisticInfo>;
using StatisticsIterator = Statistics::iterator;

static Statistics opStatistics;
static std::mutex mutexStats;
static std::mutex gateMutex;
static std::condition_variable gate;
static bool iteratorReady = false;
static bool continueHandler = false;

StatisticsIterator GetUserStatistics(uint32_t userId)
{
    std::lock_guard<std::mutex> lock(mutexStats);
    auto it = opStatistics.find(userId);
    if (it != opStatistics.end()) {
        return it;
    }
    RadarStatisticInfo radarInfo = {};
    return opStatistics.insert(std::make_pair(userId, radarInfo)).first;
}

void GetTempStatistics(Statistics &statistics)
{
    std::lock_guard<std::mutex> lock(mutexStats);
    statistics.insert(opStatistics.begin(), opStatistics.end());
    opStatistics.clear();
}

int main()
{
    StatisticsIterator escaped;
    std::thread handler([&] {
        escaped = GetUserStatistics(100);
        {
            std::lock_guard<std::mutex> lock(gateMutex);
            iteratorReady = true;
        }
        gate.notify_one();
        {
            std::unique_lock<std::mutex> lock(gateMutex);
            gate.wait(lock, [] { return continueHandler; });
        }
        // The getter's mutex is no longer held here. The iterator's map node
        // may have been freed by GetTempStatistics.
        escaped->second.userStartFailCount++;
    });

    {
        std::unique_lock<std::mutex> lock(gateMutex);
        gate.wait(lock, [] { return iteratorReady; });
    }

    Statistics snapshot;
    GetTempStatistics(snapshot); // clears map while iterator is outstanding
    {
        std::lock_guard<std::mutex> lock(gateMutex);
        continueHandler = true;
    }
    gate.notify_one();
    handler.join();
    std::cout << "unexpectedly completed: " << escaped->second.userStartFailCount << "\n";
    return 0;
}
