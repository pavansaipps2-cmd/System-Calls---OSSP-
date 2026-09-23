#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program-to-trace>\n", argv[0]);
        exit(1);
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        exit(1);
    }

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        exit(1);
    } else {
        int status;
        long syscall_count = 0;
        
        printf("[*] Tracing started for PID: %d\n", child);
        
        waitpid(child, &status, 0);
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

        while (WIFSTOPPED(status)) {
            struct user_regs_struct regs;
            
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) {
                perror("ptrace");
                break;
            }
            
            waitpid(child, &status, 0);
            if (WIFEXITED(status)) break;

            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0) {
                perror("ptrace_getregs");
                break;
            }

            printf("System Call ID: %lld\n", regs.orig_rax);
            syscall_count++;

            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) {
                perror("ptrace");
                break;
            }
            waitpid(child, &status, 0);
        }
        
        printf("[*] Tracing finished. Total system calls intercepted: %ld\n", syscall_count);
    }

    return 0;
}