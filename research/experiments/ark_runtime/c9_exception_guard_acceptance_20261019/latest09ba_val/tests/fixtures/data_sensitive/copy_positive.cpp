// Original synthetic D regression fixture; not a real vulnerability.
void f(SessionKey *x){ char out[100]; memcpy_s(out,100,x->value,32); AUTH_LOGI(0,"%{public}s",out); }
