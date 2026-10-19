#include <algorithm>
#include <array>
#include <string_view>

bool copy_checked(std::string_view input, std::array<char, 8>& destination) {
    if (input.size() >= destination.size()) {
        return false;
    }
    std::copy(input.begin(), input.end(), destination.begin());
    destination[input.size()] = '\0';
    return true;
}

int main() {
    std::array<char, 8> buffer{};
    return copy_checked("safe", buffer) ? 0 : 1;
}
