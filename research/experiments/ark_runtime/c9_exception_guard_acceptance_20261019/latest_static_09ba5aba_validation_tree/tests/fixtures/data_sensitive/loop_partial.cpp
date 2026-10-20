// Original synthetic D regression fixture; not a real vulnerability.
void f(SessionKey *x){ while(1){ AUTH_LOGI(0,"%{public}s",x->value); } }
