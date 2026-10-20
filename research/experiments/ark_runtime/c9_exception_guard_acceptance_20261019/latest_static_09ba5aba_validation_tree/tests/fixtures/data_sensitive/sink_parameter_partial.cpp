// Original synthetic regression, not an official vulnerability.
void f(SessionKey *x, void (*AUTH_LOGI)(int,const char*,const void*)){ AUTH_LOGI(0,"%{public}s",x->value); }
