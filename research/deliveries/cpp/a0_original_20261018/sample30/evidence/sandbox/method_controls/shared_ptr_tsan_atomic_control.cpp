// Generic fixed control using atomic shared_ptr access. It is not evidence about any sampled component.
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
            std::atomic_store_explicit(&sp, next, std::memory_order_release);
        }
    });
    std::thread reader([&] {
        long long sum = 0;
        for (int i = 0; i < 200000; ++i) {
            auto local = std::atomic_load_explicit(&sp, std::memory_order_acquire);
            if (local) sum += *local;
        }
        std::cout << "reader_sum=" << sum << "\n";
    });
    reader.join();
    stop.store(true, std::memory_order_relaxed);
    writer.join();
    std::cout << "atomic_shared_ptr_control_complete\n";
    return 0;
}
