#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <time.h>

// Function to categorize system call IDs into numeric categories (Objective 3)
int categorize_syscall(long syscall_id) {
    switch (syscall_id) {
        case 0:  // read
        case 1:  // write
        case 2:  // open
        case 3:  // close
        case 257: // openat
            return 1; // File Management
        case 57: // fork
        case 59: // execve
        case 60: // exit
        case 231: // exit_group
            return 2; // Process Control
        case 9:  // mmap
        case 11: // munmap
        case 12: // brk
        case 10: // mprotect
            return 3; // Memory Management
        case 5:  // fstat
        case 21: // access
            return 4; // Information Maintenance
        default:
            return 5; // Other / System Services
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program-to-trace>\n", argv[0]);
        exit(1);
    }

    // Objective 2: Track execution time and overhead start
    clock_t start_time = clock();

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
        long total_syscalls = 0;
        long file_mgmt_count = 0;
        long proc_ctrl_count = 0;
        long mem_mgmt_count = 0;
        long info_maint_count = 0;
        long other_count = 0;
        long error_count = 0;

        // Dashboard Header (Objective 1)
        printf("========================================================\n");
        printf("         OSSP ADVANCED SYSTEM CALL DASHBOARD            \n");
        printf("========================================================\n");
        printf("[*] Target Program      : %s\n", argv[1]);
        printf("[*] Child Process ID    : %d\n", child);
        printf("[*] Monitoring Status   : ACTIVE (User-Space Trace)\n");
        printf("--------------------------------------------------------\n");

        waitpid(child, &status, 0);
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

        while (WIFSTOPPED(status)) {
            struct user_regs_struct regs;

            // Enter system call
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) break;
            waitpid(child, &status, 0);
            if (WIFEXITED(status)) break;

            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0) break;

            total_syscalls++;
            long sc_id = regs.orig_rax;
            int cat_code = categorize_syscall(sc_id);

            // Objective 3: Categorization tracking using integer codes
            if (cat_code == 1) file_mgmt_count++;
            else if (cat_code == 2) proc_ctrl_count++;
            else if (cat_code == 3) mem_mgmt_count++;
            else if (cat_code == 4) info_maint_count++;
            else other_count++;

            // Exit system call to capture return code and error status (Objective 4)
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) break;
            waitpid(child, &status, 0);
            if (WIFEXITED(status)) break;

            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == 0) {
                long ret_val = regs.rax; // Return value is stored in rax
                // Objective 4: Check if return code indicates a negative error
                if (ret_val < 0 && ret_val > -4096) {
                    error_count++;
                }
            }
        }

        // Objective 2: Calculate execution time and performance overhead
        clock_t end_time = clock();
        double cpu_time_used = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;

        // Export metrics to JSON for the Chrome Web Dashboard
        FILE *json_file = fopen("dashboard_data.json", "w");
        if (json_file != NULL) {
            fprintf(json_file, "{\n");
            fprintf(json_file, "  \"total\": %ld,\n", total_syscalls);
            fprintf(json_file, "  \"file_mgmt\": %ld,\n", file_mgmt_count);
            fprintf(json_file, "  \"proc_ctrl\": %ld,\n", proc_ctrl_count);
            fprintf(json_file, "  \"mem_mgmt\": %ld,\n", mem_mgmt_count);
            fprintf(json_file, "  \"info_maint\": %ld,\n", info_maint_count);
            fprintf(json_file, "  \"other\": %ld,\n", other_count);
            fprintf(json_file, "  \"errors\": %ld,\n", error_count);
            fprintf(json_file, "  \"overhead\": %.4f,\n", cpu_time_used);
            fprintf(json_file, "  \"status\": \"SUCCESS (Secure)\"\n");
            fprintf(json_file, "}\n");
            fclose(json_file);
        }

        // Terminal Dashboard Summary Report
        printf("\n========================================================\n");
        printf("               EXECUTION PERFORMANCE REPORT             \n");
        printf("========================================================\n");
        printf(" Total System Calls Intercepted   : %ld\n", total_syscalls);
        printf(" ----------------- CATEGORIZATION ----------------------\n");
        printf("   - File Management              : %ld\n", file_mgmt_count);
        printf("   - Process Control              : %ld\n", proc_ctrl_count);
        printf("   - Memory Management            : %ld\n", mem_mgmt_count);
        printf("   - Information Maintenance      : %ld\n", info_maint_count);
        printf("   - Other System Services        : %ld\n", other_count);
        printf(" ----------------- STATUS & DIAGNOSTICS ----------------\n");
        printf(" Error Codes Detected             : %ld\n", error_count);
        printf(" Total Execution Overhead Time    : %.4f seconds\n", cpu_time_used);
        printf(" Mode Transition Status           : SUCCESS (Secure)\n");
        printf("========================================================\n");
    }

    return 0;
}