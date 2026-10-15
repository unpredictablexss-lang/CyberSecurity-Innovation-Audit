class Widget {
public:
    void Touch() const { (void)value_; }

private:
    volatile int value_ = 0x5A5A;
};

int main()
{
    Widget widget;
    Widget* alias = &widget;
    alias->Touch();
    return 0;
}