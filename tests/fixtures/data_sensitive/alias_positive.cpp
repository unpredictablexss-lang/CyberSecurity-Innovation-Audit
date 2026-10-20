// Original synthetic D regression fixture; not a real vulnerability.
void f(SessionKey *x){ const char *a=(const char*)x->value; const char *b=a; AUTH_LOGI(0,"%{public}s",b); }
