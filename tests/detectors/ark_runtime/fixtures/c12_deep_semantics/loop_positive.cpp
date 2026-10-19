void Emit() {
    Label again(GetEnvironment());
    Jump(&again);
    LoopBegin(&again);
    LoopEnd(&again);
}
