#define LOG_FORMAT "%s"

void log_value(FILE* stream, const char* value) {
    fprintf(stream, "[LOG] " LOG_FORMAT "\n", value);
}
