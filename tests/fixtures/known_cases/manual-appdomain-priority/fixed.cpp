void ScheduleVerifyTasks() { for (auto &uri : uris_) PostTask(uri, callback_); }
void OnUriCallback() { std::lock_guard<std::mutex> guard(mutex_); uint32_t priority = appVerifyBaseInfo_.priority; use(priority); }
