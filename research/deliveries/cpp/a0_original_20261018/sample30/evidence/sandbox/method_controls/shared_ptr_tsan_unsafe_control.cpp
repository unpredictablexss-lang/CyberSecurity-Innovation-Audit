// Generic shared_ptr race positive control. It is not evidence about any sampled component.
#include <atomic>
#include <iostream>
#include <memory>
#include <thread>
int main() {
    auto sp = std::make_shared<int>(1);
    std::atomic<bool> stop{false};
    std::thread writer([&] {
        for (int i = 2; !stop.load(std::memory_order_relaxed); ++i) {
            auto next = std::make_shared<int>(i);
            sp = next;
        }
    });
    std::thread reader([&] {
        long long sum = 0;
        for (int i = 0; i < 200000; ++i) {
            auto local = sp;
            if (local) sum += *local;
        }
        std::cout << "reader_sum=" << sum << "\n";
    });
    reader.join();
    stop.store(true, std::memory_order_relaxed);
    writer.join();
    std::cout << "unsafe_shared_ptr_control_complete\n";
    return 0;
}
