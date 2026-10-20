// SYNTHETIC UNRELATED CONTROL for the integer narrowing root cause in CVE-2025-0587.
// This display-metric conversion has no offset multiplication or memory sink.
int32_t DoubleInRangeInt32(double value);

int32_t metric_bucket(double value, int32_t bucket_count) {
    const int32_t bucket = DoubleInRangeInt32(value);
    if (bucket >= bucket_count) {
        return -1;
    }
    return bucket;
}
