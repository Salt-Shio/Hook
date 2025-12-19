#include <stdio.h>
#include <unistd.h>

__attribute__((constructor))
void init() {
    printf("Inject Success\n");
}