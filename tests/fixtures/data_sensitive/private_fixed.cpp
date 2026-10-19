// Original synthetic D regression fixture; not a real vulnerability.
void f(SessionKey *x){ AUTH_LOGE(0,"%{private}s",x->value); }
