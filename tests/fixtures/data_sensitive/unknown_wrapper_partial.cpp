// Original synthetic D regression fixture; not a real vulnerability.
void f(SessionKey *x){ const char *a=Mask(x->value); AUTH_LOGI(0,"%{public}s",a); }
