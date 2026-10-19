void Emit() {
    Label again(GetEnvironment());
    Label exit(GetEnvironment());
    LoopBegin(&again);
    Jump(&exit);
}
