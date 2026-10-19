void GetUserStatistics() { std::lock_guard<std::mutex> guard(mutexStats_); use(opStatistics_); }
void StorageRadarThd() { std::lock_guard<std::mutex> guard(mutexStats_); if (opStatistics_.empty()) return; publish(); }
