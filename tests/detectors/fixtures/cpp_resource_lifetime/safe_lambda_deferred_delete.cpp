struct Manager {
    void Start();
};

void deferred(Manager *manager)
{
    auto callback = [=]() {
        delete manager;
    };
    (void)callback;
    manager->Start();
}
