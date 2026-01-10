// g++ ./inject_lib/inject_lib.cpp -shared -o ./bin/inject_lib.so

#include <stdio.h>
#include <unistd.h>

#define TRAMPOLINE_MARKER1 0x9090909090909090

__attribute__((constructor))
void init() {
    printf("Inject Success\n");
}

extern "C" {
    void hook_1() {
        printf("Hooked! Logic here.\n");
    }

    __attribute__((naked)) void bridge_1() {
        __asm__ __volatile__(
            ".intel_syntax noprefix \n"
            "push rax; push rcx; push rdx; push rsi; push rdi; push r8; push r9; push r10; push r11;"
            "call hook_1;"
            "pop r11; pop r10; pop r9; pop r8; pop r11; pop rsi; pop rdx; pop rcx; pop rax;"
            
            "trampoline_zone:"
            ".quad 0x9090909090909090;" 
            ".quad 0x9090909090909090;"
            ".quad 0x9090909090909090;"
            ".quad 0x9090909090909090;"
        );
    }
}