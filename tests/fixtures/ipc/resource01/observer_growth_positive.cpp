class PasteStub {
  int OnSubscribeObserver(Parcel &data) {
    auto callback = ReadObserver(data);
    SubscribeObserver(callback);
    return 0;
  }
};
class PasteService : public PasteStub {
  void SubscribeObserver(Observer *observer) { AddObserver(observer); }
  void AddObserver(Observer *observer) { observers.insert(observer); }
};
