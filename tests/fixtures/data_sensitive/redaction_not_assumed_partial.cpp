// Original synthetic regression, not an official vulnerability.
void f(SessionKey *x){ const char *p=HashOrTruncate(x->value); AUTH_LOGI(0,"%{public}s",p); }
