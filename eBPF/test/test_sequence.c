#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/wait.h>

static sigjmp_buf env;

void handler(int sig) {
    printf("Signal %d reçu (page fault intercepté)\n", sig);
    siglongjmp(env, 1);
}

void memory_activity() {
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }

    printf("mmap address: %p\n", addr);
    ((char *)addr)[0] = 42;

    if (madvise(addr, 4096, MADV_DONTNEED) != 0) {
        perror("madvise failed");
    } else {
        printf("madvise called on %p\n", addr);
    }

    if (sigsetjmp(env, 1) == 0) {
        volatile char val = ((char *)addr)[0];
        printf("val=%d (lecture après madvise)\n", val);
    } else {
        printf("Page fault détectée après madvise sur %p\n", addr);
    }

    if (munmap(addr, 4096) != 0) {
        perror("munmap failed");
        exit(1);
    } else {
        printf("munmap called on %p\n", addr);
    }

    if (sigsetjmp(env, 1) == 0) {
        volatile char val2 = ((char *)addr)[0];
        printf("val=%d (lecture après munmap)\n", val2);
    } else {
        printf("Page fault détectée après munmap sur %p\n", addr);
    }
}

int main() {
    signal(SIGSEGV, handler);

    while (1) {
        pid_t child = fork();
        if (child == 0) {
            printf("Child process PID=%d (parent=%d)\n", getpid(), getppid());
            memory_activity();
            exit(42); 
        } else if (child > 0) {
            printf("Parent PID=%d forked child PID=%d\n", getpid(), child);
            memory_activity();

            int status;
            waitpid(child, &status, 0);
            if (WIFEXITED(status)) {
                printf("Child PID=%d exited with status %d\n", child, WEXITSTATUS(status));
            } else {
                printf("Child PID=%d did not exit cleanly\n", child);
            }
        } else {
            perror("fork failed");
            exit(1);
        }

        sleep(1);
    }

    return 0;
}
