void AddUnrelatedObserver(Observer *observer){ if(!observer)return; observers->insert(observer); }
UnrelatedServiceStub::UnrelatedServiceStub(){ memberFuncMap_[GET_PASTE_DATA] = &UnrelatedServiceStub::OnGetPasteData; }
int OnRemoteRequest(int code){ auto it=memberFuncMap_.find(code); if(it!=memberFuncMap_.end()) return (this->*it->second)(); return 0; }
int OnGetPasteData(){ GetPasteData(); reply.WriteParcelable(data); return 0; }
