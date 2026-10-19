// Original synthetic regression, no real vulnerability.
void f(SessionKey *x){ bool b=x->value!=0; AUTH_LOGI(0,"%{public}d",b); }
