#define DEREFERENCE(value) (*(value))

int unknown_macro_shape(const int *value) {
    return DEREFERENCE(value);
}
