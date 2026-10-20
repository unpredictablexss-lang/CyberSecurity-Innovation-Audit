// Original synthetic D regression fixture; not a real vulnerability.
void f(SessionKey *x){ AUTH_LOGI(0,"%{public}u",x->len); }
