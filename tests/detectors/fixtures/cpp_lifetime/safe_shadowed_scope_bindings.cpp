struct A {
    void Use() const {}
};

struct B {
    void Use() const {}
};

void sibling_scope_names_are_distinct() {
    {
        std::unique_ptr<A> owner;
        A* alias = owner.get();
        owner.reset();
    }
    {
        std::unique_ptr<B> owner;
        B* alias = owner.get();
        alias = owner.get();
        alias->Use();
    }
}

void nested_shadowing_is_distinct() {
    std::unique_ptr<A> owner;
    A* alias = owner.get();
    owner.reset();
    {
        std::unique_ptr<B> owner;
        B* alias = owner.get();
        alias = owner.get();
        alias->Use();
    }
}
