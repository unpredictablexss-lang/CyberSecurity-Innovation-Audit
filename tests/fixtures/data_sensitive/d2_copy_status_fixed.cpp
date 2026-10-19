// Original synthetic D2 regression; not historical or holdout.
void Callback(const char *secret,int cond){char out[64]; int rc=memcpy_s(out,64,secret,32); AUTH_LOGI(0,"%{public}d",rc);}
