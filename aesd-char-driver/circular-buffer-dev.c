#include <stdlib.h>
#include <stdio.h>
#include "aesd-circular-buffer.h"

#define STR_SIZE 32

int main() {
    struct aesd_circular_buffer buffer;
    aesd_circular_buffer_init(&buffer);

    for (int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED * 3; i++) {
        // Allocate string stored in entry
        char *strptr = malloc(STR_SIZE);
        if (!strptr) {
            perror("malloc");
            return 1;
        }
        int written = snprintf(strptr, STR_SIZE, "%d", i);
        if (written < 0 || written >= STR_SIZE) {
            fprintf(stderr, "snprintf failed/overflow\n");
            free(strptr);
            return 1;
        }

        struct aesd_buffer_entry entry = {
            .buffptr = strptr,
            .size = (size_t)written
        };
        aesd_circular_buffer_add_entry(&buffer, &entry);

        // Prints
        printf("%d [in: %d, out: %d]: ", i, buffer.in_offs, buffer.out_offs);
        aesd_circular_buffer_print(&buffer);
    }
}