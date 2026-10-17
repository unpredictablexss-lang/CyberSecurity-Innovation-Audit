#include <iostream>
#include <string>
#include <vector>

struct ElementAccessor {
    std::vector<int> &values;
    int Get(size_t index) const {
        return index < values.size() ? values[index] : -1;
    }
    void Set(size_t index, int value) {
        if (index < values.size()) {
            values[index] = value;
        }
    }
};

void SortElementsByObject(std::vector<int> &values) {
    ElementAccessor accessor{values};
    const size_t len = values.size();
    bool changed = false;
    auto compare = [&](int left, int right) {
        if (!changed) {
            changed = true;
            values.resize(1);
        }
        return left < right;
    };
    for (size_t i = 1; i < len; ++i) {
        int present = accessor.Get(i);
        size_t begin = 0;
        size_t end = i;
        while (begin < end) {
            size_t middle = (begin + end) / 2;
            int middleValue = accessor.Get(middle);
            if (compare(middleValue, present)) {
                begin = middle + 1;
            } else {
                end = middle;
            }
        }
        for (size_t j = i; j > end; --j) {
            int previous = accessor.Get(j - 1);
            accessor.Set(j, previous);
        }
        accessor.Set(end, present);
    }
    std::cout << "fixed path completed size=" << values.size() << "\n";
}

int main() {
    std::vector<int> values(20);
    for (size_t i = 0; i < values.size(); ++i) {
        values[i] = static_cast<int>(i);
    }
    SortElementsByObject(values);
    return 0;
}
