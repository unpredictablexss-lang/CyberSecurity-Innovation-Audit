#include <memory>

class Holder {
public:
    static std::shared_ptr<int> instance_;
};
