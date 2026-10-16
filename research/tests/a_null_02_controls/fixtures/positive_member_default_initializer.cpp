struct Item {
    int id;
};

class Holder {
public:
    int Read() const {
        return item_->id;
    }

private:
    Item *item_ = nullptr;
};
