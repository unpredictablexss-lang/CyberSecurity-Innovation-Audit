// Original synthetic D regression fixture; not a real vulnerability.
void f(SessionKey *x){ char out[100]; snprintf(out,100,"%s",x->value); AUTH_LOGI(0,"%{public}s",out); }
