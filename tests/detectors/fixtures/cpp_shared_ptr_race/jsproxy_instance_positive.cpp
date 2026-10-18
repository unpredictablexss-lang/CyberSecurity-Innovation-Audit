#include <memory>
#include <utility>

class JSProxy {
public:
    void SetInstance(std::shared_ptr<int> instance)
    {
        instance_ = std::move(instance);
    }

    std::shared_ptr<int> GetInstance() const
    {
        return instance_;
    }

private:
    std::shared_ptr<int> instance_;
};
