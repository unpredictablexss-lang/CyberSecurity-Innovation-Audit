void ScheduleVerifyTasks() { for (auto &uri : uris_) PostTask(uri, callback_); }
void OnUriCallback() { uint32_t priority = appVerifyBaseInfo_.priority.load(); use(priority); }
