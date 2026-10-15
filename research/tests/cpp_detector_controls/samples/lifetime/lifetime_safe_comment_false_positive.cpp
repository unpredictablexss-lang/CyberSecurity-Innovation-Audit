#include <memory>

class Widget {
public:
    void Touch() const { (void)value_; }

private:
    volatile int value_ = 0x5A5A;
};

int main()
{
    // False-positive shape: owner.reset(); alias->Use(); appears only in a comment.
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
    const char* text = "owner.reset(); alias->Use();";
    (void)text;
    alias->Touch();
    return 0;
}