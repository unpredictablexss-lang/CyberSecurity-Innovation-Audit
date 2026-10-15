#include <thread>
#include <vector>

class Widget {
public:
    void Touch() const {}
};

int main()
{
    Widget widget;
    Widget* stable_pointer = &widget;
    std::vector<std::thread> threads;
    for (int index = 0; index < 2; ++index) {
        threads.emplace_back([stable_pointer]() {
            for (int step = 0; step < 10000; ++step) {
                stable_pointer->Touch();
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    return 0;
}