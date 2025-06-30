#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <setjmp.h>

static sigjmp_buf env;

void handler(int sig) {
    printf("Signal %d reçu (page fault intercepté)\n", sig);
    siglongjmp(env, 1);
}

int main() {
    // Catcher le segfault pour ne pas crasher
    signal(SIGSEGV, handler);

    while (1) {
        void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED) {
            perror("mmap failed");
            exit(1);
        }

        printf("mmap address: %p\n", addr);

        // Écrire une valeur
        ((char *)addr)[0] = 42;

        if (madvise(addr, 4096, MADV_DONTNEED) != 0) {
            perror("madvise failed");
        } else {
            printf("madvise called on %p\n", addr);
        }

        // ⚠️ Provoquer une page fault en relisant après MADV_DONTNEED
        if (sigsetjmp(env, 1) == 0) {
            // Cette lecture va déclencher une page fault
            volatile char val = ((char *)addr)[0];
            printf("val=%d (lecture OK)\n", val);
        } else {
            printf("Page fault détectée à l'accès à %p\n", addr);
        }

        sleep(1);
    }

    return 0;
}
