void AddPasteboardChangedObserver(Observer *observer){ int pid=GetCallingPid(); if(observers->size() >= MAX_OBSERVERS_PER_PID)return; observers->insert(observer); }
PasteboardServiceStub::PasteboardServiceStub(){ memberFuncMap_[GET_PASTE_DATA] = &PasteboardServiceStub::OnGetPasteData; }
int OnRemoteRequest(int code){ auto it=memberFuncMap_.find(code); if(it!=memberFuncMap_.end()) return (this->*it->second)(); return 0; }
int OnGetPasteData(){ CheckPermission(); GetPasteData(); reply.WriteParcelable(data); return 0; }
