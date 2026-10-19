// Original synthetic D2 regression; not historical or holdout.
void Callback(const char *secret,int cond){int (*strcpy_s)(char*,int,const char*)=OtherCopy; char out[64]; strcpy_s(out,64,secret); AUTH_LOGI(0,"%{public}s",out);}
