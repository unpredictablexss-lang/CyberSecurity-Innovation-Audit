GateRef DataViewGet(GateRef glue, uint64_t index) {
    GateRef offset = CalculatePositionWithLength(glue, index);
    return GetValueInBuffer(glue, offset);
}
