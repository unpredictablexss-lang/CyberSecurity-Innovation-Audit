template <typename T>
struct Box {
    T *value;
};

template <typename T>
int unknown_template_shape(const Box<T> &box) {
    return *box.value;
}
