void OnRemoteRequest() { int32_t len = data.ReadInt32(); if (len < 0) return; void *p = malloc(len); consume(p); }
