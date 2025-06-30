#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    while (1) {
        void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED) {
            perror("mmap failed");
            exit(1);
        }

        printf("mmap address: %p\n", addr);
        sleep(1);
    }

    return 0;
}
