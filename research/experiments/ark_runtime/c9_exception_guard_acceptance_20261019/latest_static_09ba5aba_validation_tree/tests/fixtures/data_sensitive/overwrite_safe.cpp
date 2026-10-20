// Original synthetic D regression fixture; not a real vulnerability.
void f(SessionKey *x){ const char *a=(const char*)x->value; a="redacted"; AUTH_LOGI(0,"%{public}s",a); }
