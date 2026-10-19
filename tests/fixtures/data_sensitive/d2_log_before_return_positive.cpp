// Original synthetic D2 regression; not historical or holdout.
void Callback(const char *secret,int cond){if(cond){AUTH_LOGI(0,"%{public}s",secret);return;} AUTH_LOGI(0,"constant");}
