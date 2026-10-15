#include <memory>
#include <utility>

class Widget {
public:
    void Touch() const { (void)value_; }

private:
    volatile int value_ = 0x5A5A;
};

int main()
{
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
    {
        std::unique_ptr<Widget> next = std::move(owner);
        (void)next;
    }
    alias->Touch();
    return 0;
}