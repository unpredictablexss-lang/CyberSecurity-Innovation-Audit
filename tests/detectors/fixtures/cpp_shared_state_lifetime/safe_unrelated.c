struct Window { unsigned char *cursor; unsigned remaining; };
struct RasterContext { struct Window source; unsigned phase; };
void refill(struct RasterContext *state, unsigned char *bytes, unsigned amount) {
    unsigned char *input = bytes;
    if (state->source.remaining == 0) {
        state->source.cursor = input;
        state->source.remaining = amount;
        read_window(input, amount);
    }
}
void decode_window(struct RasterContext *state);
void resume_decode(struct RasterContext *state) {
    if (state->source.remaining == 0) refill(state, state->source.cursor, 16);
    if (state->source.remaining != 0) decode_window(state);
}
void walk_tree(struct RasterContext *state) { if (state->phase) walk_tree(state); }
