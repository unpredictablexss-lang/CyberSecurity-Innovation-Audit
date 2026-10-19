void OnRemoteRequest() { VerifyCallingPermission(SYSTEM_CORE); size_t len = data.ReadUint32(); void *p = calloc(1, len); consume(p); }
