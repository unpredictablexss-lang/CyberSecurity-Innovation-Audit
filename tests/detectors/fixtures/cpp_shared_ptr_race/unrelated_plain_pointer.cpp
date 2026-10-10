#include <memory>

class Unrelated {
public:
    static int* pointer_;
};

int* Unrelated::pointer_ = nullptr;

int main()
{
    return 0;
}
