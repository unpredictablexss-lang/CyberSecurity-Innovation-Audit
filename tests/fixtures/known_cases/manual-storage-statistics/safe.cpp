void GetUserStatistics() { std::lock_guard<std::mutex> guard(mutexStats_); use(opStatistics_); }
void StorageRadarThd() { auto snapshot = opStatistics_.load(); if (snapshot.empty()) return; publish(); }
