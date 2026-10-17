#include <algorithm>
#include <iostream>
#include <vector>

struct ElementAccessor {
    int *data;
    int Get(size_t index) const { return data[index]; }
    void Set(size_t index, int value) { data[index] = value; }
};

void SortElementsByObject(std::vector<int> &values, bool fixed) {
    int *raw = values.data();
    ElementAccessor accessor{raw};
    const size_t len = values.size();
    bool changed = false;
    auto compare = [&](int left, int right) {
        if (!changed) {
            changed = true;
            std::vector<int> empty;
            values.swap(empty);
            values.push_back(-1);
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
    if (fixed) {
        std::cout << "fixed path completed size=" << values.size() << "\n";
    }
}

int main(int argc, char **argv) {
    const bool fixed = argc > 1 && std::string(argv[1]) == "fixed";
    std::vector<int> values(20);
    for (size_t i = 0; i < values.size(); ++i) {
        values[i] = static_cast<int>(i);
    }
    SortElementsByObject(values, fixed);
    return 0;
}
