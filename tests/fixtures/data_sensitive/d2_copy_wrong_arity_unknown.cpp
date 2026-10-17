// Original synthetic D2 regression; not historical or holdout.
void Callback(const char *secret,int cond){char out[64]; memcpy_s(out,64,secret); AUTH_LOGI(0,"%{public}s",out);}
