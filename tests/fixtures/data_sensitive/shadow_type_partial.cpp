// Original synthetic D regression fixture; not a real vulnerability.
struct SessionKey { char value[32]; }; void f(SessionKey *x){ AUTH_LOGI(0,"%{public}s",x->value); }
