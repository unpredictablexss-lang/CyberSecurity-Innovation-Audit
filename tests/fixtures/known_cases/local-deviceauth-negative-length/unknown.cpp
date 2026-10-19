void OnRemoteRequest() { int32_t len = data.ReadInt32(); void *p = malloc(len); consume(p); }
