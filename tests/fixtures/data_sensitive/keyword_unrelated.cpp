// Original synthetic D regression fixture; not a real vulnerability.
void f(const char *password, unsigned token){ AUTH_LOGI(0,"%{public}s %{public}u",password,token); }
