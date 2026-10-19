struct Item {
    int id;
};

class Holder {
public:
    Holder() : item_(nullptr) {}
    int Read() const {
        return item_->id;
    }

private:
    Item *item_;
};
