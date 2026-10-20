void GetUserStatistics() { std::lock_guard<std::mutex> guard(mutexStats_); use(opStatistics_); }
void StorageRadarThd() { if (localCache_.empty()) return; publish(); }
