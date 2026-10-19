#include <stdio.h>
#include <syslog.h>

void check_format_positions(FILE *stream, const char *format, va_list args) {
    fprintf(stream, "%s", format);
    fprintf(stream, format);
    vfprintf(stream, "%s", args);
    vfprintf(stream, format, args);
    printf("%s", format);
    printf(format);
    vprintf("%s", args);
    vprintf(format, args);
    syslog(LOG_INFO, "%s", format);
    syslog(LOG_INFO, format);
}
