// Original synthetic regression, no real vulnerability.
void f(){ char out[32]; int rc=SoftBusGenerateSessionKey(out,32); AUTH_LOGI(0,"%{public}d",rc); }
