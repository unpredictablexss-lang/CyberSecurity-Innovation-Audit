#include <stdlib.h>

void wrap_release(void *connection)
{
    auto callback = [](void *data) {
        void *connection = data;
        if (connection) {
            free(connection);
        }
    };
    (void)callback;
    if (connection != nullptr) {
        free(connection);
    }
}
