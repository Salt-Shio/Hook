// target.c
#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Target running. PID: %d\n", getpid());
    
    int counter = 0;
    while(1) {
        printf("I am alive... %d\n", counter++);
        sleep(2); // 每兩秒印一次
    }
    return 0;
}