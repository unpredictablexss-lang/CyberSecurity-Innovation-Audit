// Original synthetic D2 regression; not historical or holdout.
void Callback(const char *secret,int cond){const char *a="safe"; if(cond){ if(cond==2){a=secret;}else{return;} }else{return;} AUTH_LOGI(0,"%{public}s",a);}
