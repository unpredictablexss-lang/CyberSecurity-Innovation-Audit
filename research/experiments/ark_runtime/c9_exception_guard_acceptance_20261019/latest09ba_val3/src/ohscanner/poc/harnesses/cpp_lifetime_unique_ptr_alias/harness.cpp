// Controlled unique_ptr/raw-alias lifetime workload.
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <utility>

#ifndef OH_LIFETIME_VARIANT
#define OH_LIFETIME_VARIANT 0
#endif

static volatile int sink = 0;
class Widget {
public:
    explicit Widget(int value = 0x5A5A) : value_(value) {}
    void Touch() const {
        if (value_ != 0x5A5A && value_ != 0x5B5B) {
            std::abort();
        }
        sink += value_;
    }

private:
    int value_;
};

int main()
{
    std::unique_ptr<Widget> owner = std::make_unique<Widget>(0x5A5A);
    Widget* alias = owner.get();

#if OH_LIFETIME_VARIANT == 0
    owner.reset();
#elif OH_LIFETIME_VARIANT == 1
    owner = nullptr;
#elif OH_LIFETIME_VARIANT == 2
    owner = std::make_unique<Widget>(0x5B5B);
#elif OH_LIFETIME_VARIANT == 3
    {
        std::unique_ptr<Widget> next = std::move(owner);
        (void)next;
    }
#elif OH_LIFETIME_VARIANT == 4
    owner = std::make_unique<Widget>(0x5B5B);
    alias = owner.get();
#elif OH_LIFETIME_VARIANT == 5
    alias->Touch();
    owner.reset();
    std::printf("RESULT=safe_use_before_reset\n");
    return 0;
#else
#error "unknown OH_LIFETIME_VARIANT"
#endif

    alias->Touch();
    std::printf("RESULT=variant_%d_done\n", OH_LIFETIME_VARIANT);
    return 0;
}