// Original synthetic D regression fixture; not a real vulnerability.
void f(SessionKey *x,int flag){ const char *a="constant"; if(flag){ a=(const char*)x->value; } AUTH_LOGI(0,"%{public}s",a); }
