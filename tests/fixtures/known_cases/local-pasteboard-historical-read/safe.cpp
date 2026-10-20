void AddPasteboardChangedObserver(Observer *observer) {
    auto userId = GetUserId();
    auto it = observerMap_.find(userId);
    std::shared_ptr<std::set<Observer *>> observers;
    if (it != observerMap_.end()) observers = it->second;
    else { observers = std::make_shared<std::set<Observer *>>(); observerMap_.insert({userId, observers}); }
    if (observers->size() >= MAX_OBSERVERS_PER_PID) return;
    observers->insert(observer);
}
PasteboardServiceStub::PasteboardServiceStub(){ memberFuncMap_[GET_PASTE_DATA] = &PasteboardServiceStub::OnGetPasteData; }
int OnRemoteRequest(int code){ auto it=memberFuncMap_.find(code); if(it!=memberFuncMap_.end()) return (this->*it->second)(); return 0; }
bool CheckPastePermission(){ if (permissionMap[PERMISSION_READ_PASTEBOARD] != PERMISSION_GRANTED) return false; return true; }
int OnGetPasteData(){ if (!CheckPastePermission()) return ERR_NO_PERMISSION; GetPasteData(); reply.WriteParcelable(data); return 0; }
