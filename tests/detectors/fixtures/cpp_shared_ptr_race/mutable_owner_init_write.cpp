#include <memory>
#include <utility>

class Holder {
public:
    void Init(std::shared_ptr<int> value)
    {
        value_ = std::move(value);
    }

    std::shared_ptr<int> Get() const
    {
        return value_;
    }

private:
    std::shared_ptr<int> value_;
};
