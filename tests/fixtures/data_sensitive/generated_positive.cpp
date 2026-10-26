// Original synthetic D regression fixture; not a real vulnerability.
void f(){ char opaque[32]; SoftBusGenerateSessionKey(opaque,32); AUTH_LOGE(0,"%{public}s",opaque); }
