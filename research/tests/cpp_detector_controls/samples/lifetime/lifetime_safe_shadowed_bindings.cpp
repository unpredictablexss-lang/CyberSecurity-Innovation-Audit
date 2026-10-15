#include <memory>

class FirstWidget {
public:
    void Touch() const {}
};

class SecondWidget {
public:
    void Touch() const {}
};

int main()
{
    {
        std::unique_ptr<FirstWidget> owner = std::make_unique<FirstWidget>();
        FirstWidget* alias = owner.get();
        owner.reset();
    }
    {
        std::unique_ptr<SecondWidget> owner = std::make_unique<SecondWidget>();
        SecondWidget* alias = owner.get();
        alias->Touch();
    }
    return 0;
}