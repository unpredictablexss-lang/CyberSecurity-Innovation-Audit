void Emit() {
    Label again(GetEnvironment());
    Label exit(GetEnvironment());
    Jump(&again);
    LoopBegin(&again);
    Jump(&exit);
}
