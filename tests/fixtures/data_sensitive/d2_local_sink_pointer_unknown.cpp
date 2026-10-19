// Original synthetic D2 regression; not historical or holdout.
void Callback(const char *secret,int cond){void (*AUTH_LOGI)(int,const char*,const char*)=OtherLog; AUTH_LOGI(0,"%{public}s",secret);}
