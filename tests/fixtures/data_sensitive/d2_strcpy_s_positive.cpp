// Original synthetic D2 regression; not historical or holdout.
void Callback(const char *secret,int cond){char buf[64]; strcpy_s(buf,64,secret); AUTH_LOGI(0,"%{public}s",buf);}
