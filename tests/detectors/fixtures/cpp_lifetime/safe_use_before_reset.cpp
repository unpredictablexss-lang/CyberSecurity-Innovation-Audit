#include <memory>
#include <mutex>

struct Widget {
    int Value() const { return 7; }
};

void consume(int) {}

void safe_use_precedes_reset() {
    std::mutex mutex;
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
    std::lock_guard<std::mutex> lock(mutex);
    consume(alias->Value());
    owner.reset();
}
