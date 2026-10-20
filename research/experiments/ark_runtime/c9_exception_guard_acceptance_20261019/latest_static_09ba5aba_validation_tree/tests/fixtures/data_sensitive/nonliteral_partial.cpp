// Original synthetic D regression fixture; not a real vulnerability.
void f(SessionKey *x,const char *fmt){ AUTH_LOGI(0,fmt,x->value); }
