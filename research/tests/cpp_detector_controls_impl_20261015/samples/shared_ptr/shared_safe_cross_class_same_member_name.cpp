#include <memory>

class Widget {
public:
    void Touch() const {}
};

class ReadOnlyHolder {
public:
    static std::shared_ptr<Widget> First()
    {
        return instance_;
    }

    static std::shared_ptr<Widget> Second()
    {
        return instance_;
    }

private:
    static std::shared_ptr<Widget> instance_;
};

class OtherHolder {
public:
    static std::shared_ptr<Widget> Load()
    {
        return instance_;
    }

private:
    static std::shared_ptr<Widget> instance_;
};

std::shared_ptr<Widget> ReadOnlyHolder::instance_;
std::shared_ptr<Widget> OtherHolder::instance_;

int main()
{
    auto first = ReadOnlyHolder::First();
    auto second = ReadOnlyHolder::Second();
    if (first != nullptr) {
        first->Touch();
    }
    if (second != nullptr) {
        second->Touch();
    }
    auto other = OtherHolder::Load();
    if (other != nullptr) {
        other->Touch();
    }
    return 0;
}