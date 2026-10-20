GateRef DataViewGet(GateRef glue, int32_t index) {
    GateRef offset = CalculatePositionWithLength(glue, index);
    return GetValueInBuffer(glue, offset);
}
