#include <memory>
#include <mutex>

struct Widget {
    int Value() const { return 7; }
};

void consume(int) {}

void vulnerable_inside_mutex() {
    std::mutex mutex;
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
    std::lock_guard<std::mutex> lock(mutex);
    owner.reset();
    consume(alias->Value());
}
