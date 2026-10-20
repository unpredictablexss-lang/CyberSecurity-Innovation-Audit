// Original synthetic D2 regression; not historical or holdout.
void Callback(const char *secret,int cond){const char *a=secret; if(cond){return;}else{a="safe";} AUTH_LOGI(0,"%{public}s",a);}
