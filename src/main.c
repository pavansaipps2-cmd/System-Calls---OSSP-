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
        long write_count = 0;
        long other_count = 0;
        
        // Dashboard Header Interface
        printf("==================================================\n");
        printf("       OSSP SYSTEM CALL MONITOR DASHBOARD         \n");
        printf("==================================================\n");
        printf("[*] Target Program : %s\n", argv[1]);
        printf("[*] Child PID      : %d\n", child);
        printf("[*] Status         : RUNNING & TRACING...\n");
        printf("--------------------------------------------------\n");
        
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

            syscall_count++;
            if (regs.orig_rax == 1) { // Syscall 1 is typically write on x86_64
                write_count++;
            } else {
                other_count++;
            }

            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) {
                perror("ptrace");
                break;
            }
            waitpid(child, &status, 0);
        }
        
        // Dashboard Footer / Analytics Report Interface
        printf("\n==================================================\n");
        printf("              EXECUTION SUMMARY REPORT            \n");
        printf("==================================================\n");
        printf(" Total System Calls Intercepted : %ld\n", syscall_count);
        printf(" Write System Calls (ID 1)      : %ld\n", write_count);
        printf(" Other System Calls             : %ld\n", other_count);
        printf(" Mode Transitions Status        : SUCCESS\n");
        printf("==================================================\n");
    }

    return 0;
}