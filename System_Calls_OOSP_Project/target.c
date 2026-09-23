#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Target program running...\n");
    write(1, "Hello via write syscall!\n", 25);
    return 0;
}