int ConvertMetric() {
    JSTaggedNumber index = JSTaggedValue::ToIndex(thread, firstArg);
    int32_t metric = 0;
    metric = static_cast<int32_t>(index.GetNumber());
    print(metric);
    return metric;
}
