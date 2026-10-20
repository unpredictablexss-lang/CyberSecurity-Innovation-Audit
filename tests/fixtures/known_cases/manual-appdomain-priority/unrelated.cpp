void ScheduleVerifyTasks() { for (auto &uri : uris_) PostTask(uri, callback_); }
void OnUriCallback() { uint32_t priority = localPriority_; use(priority); }
