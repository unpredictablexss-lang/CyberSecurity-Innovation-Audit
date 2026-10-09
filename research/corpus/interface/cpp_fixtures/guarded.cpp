// Synthetic design fixture; not an OpenHarmony vulnerability.
void Handle(int caller, bool flag) { if (!Allowed(caller)) return; Sensitive(); }
