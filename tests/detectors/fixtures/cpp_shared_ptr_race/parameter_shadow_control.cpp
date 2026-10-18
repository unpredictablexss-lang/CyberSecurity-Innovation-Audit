#include <memory>

struct Option {
    void Run();
};

class Holder {
public:
    void Set(std::shared_ptr<Option> value)
    {
        option = value;
    }

    std::shared_ptr<Option> Get() const
    {
        return option;
    }

    void Use(Option *option)
    {
        option->Run();
    }

private:
    std::shared_ptr<Option> option;
};
