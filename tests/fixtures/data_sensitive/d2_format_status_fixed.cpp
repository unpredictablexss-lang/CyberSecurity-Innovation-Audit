// Original synthetic D2 regression; not historical or holdout.
void Callback(const char *secret,int cond){char buf[64]; int rc=snprintf_s(buf,64,63,"%s",secret); AUTH_LOGI(0,"%{public}d",rc);}
