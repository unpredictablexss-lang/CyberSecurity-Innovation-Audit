int unrelated_null_words() {
    // A textual nullptr dereference control must not create a source/sink pair.
    const char *message = "return *nullptr;";
    return message == nullptr;
}
