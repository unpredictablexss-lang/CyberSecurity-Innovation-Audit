#include <stdlib.h>
struct Window { unsigned char *cursor; unsigned remaining; };
struct RasterContext { struct Window source; unsigned phase; unsigned char *owned; };
void refill(struct RasterContext *state, unsigned char *bytes, unsigned amount) {
    unsigned char *input = bytes;
    if (state->source.remaining == 0) {
        state->source.cursor = input;
        state->source.remaining = amount;
        read_window(input, amount);
    }
}
void release_segment(struct RasterContext *state) {
    free(state->owned);
    state->phase = 0;
}
void decode_window(struct RasterContext *state) {
    volatile unsigned char sample = state->source.cursor[0];
    (void)sample;
}
void resume_decode(struct RasterContext *state) {
    if (state->source.remaining == 0) {
        refill(state, state->owned, 16);
    }
    if (state->source.remaining != 0) decode_window(state);
}
