// Original synthetic D regression fixture; not a real vulnerability.
void AUTH_LOGI(int l,const char *f,const char *p){} void f(SessionKey *x){ AUTH_LOGI(0,"%{public}s",x->value); }
