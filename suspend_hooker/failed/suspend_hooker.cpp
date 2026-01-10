// g++ ./suspend_hooker/suspend_hooker.cpp ./utils/utils.cpp -Iutils -o ./bin/suspend_hooker
#include "utils.h"

struct TargetAddress {
    u_int64_t target_base;
    TargetAddress(u_int64_t target_base) {
        this->target_base = target_base;
    }

    u_int64_t main_offset() {return target_base + 0x1189;}
    u_int64_t hook1_offset() {return target_base + 0x11b0;}
    u_int64_t hook1_end_offset() {return target_base + 0x11c0;}
};

struct InjectLibAddress {
    u_int64_t inject_lib_base;
    InjectLibAddress(u_int64_t inject_lib_base) {
        this->inject_lib_base = inject_lib_base;
    }

    u_int64_t bridge1_offset() {return inject_lib_base + 0x116d;}
    u_int64_t bridge1_trampoline() {return inject_lib_base + 0x1191;}
};

int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("[USAGE] %s [target]\n", argv[0]);
        return 0;
    }

    const char* target_path = argv[1];

    pid_t pid = fork(); 
    // 這裡會分出兩個一模一樣的程式，pid != 0 這個 pid 是子進程的 pid，pid == 0 表示自己是 子行程，因此要有兩個分支

    if (pid == 0) { // Target
        setenv("LD_PRELOAD", "./inject_lib.so", 1);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // 用 0 表示 trace 自己，這裡用 getpid 應該也能跑
        execl(target_path, target_path, NULL); // 跑起 elf，整個程式會換成 program_path 的內容
        
        perror("目標執行失敗");
        exit(1);

    } else { // Hooker
        int status;
        printf("pid %d\n", pid);
        waitpid(pid, &status, 0);

        if (WIFSTOPPED(status)) {
            TargetAddress target_address(get_module_base(pid, &target_path[2]));
            printf("獲取目標 target_base address: %lx\n", target_address.target_base);
            
            std::vector<u_int8_t> read_bytes;
            std::vector<u_int8_t> write_bytes;

            // 中斷於 main 開頭
            read_bytes = read_data(pid, target_address.main_offset(), 8);
            write_bytes.assign(read_bytes.begin(), read_bytes.end());
            write_bytes[0] = 0xCC; // INT3
            write_data(pid, target_address.main_offset(), write_bytes);
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            waitpid(pid, &status, 0);

            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                InjectLibAddress inject_lib_offset(get_module_base(pid, "inject_lib.so"));
                printf("獲取目標 inject_lib_base address: %lx\n", inject_lib_offset.inject_lib_base);

                write_data(pid, target_address.main_offset(), read_bytes); // delete INT3
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                regs.rip -= 1; 
                ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                
                printf("jmp bridge1\n");
                read_bytes = read_data(pid, target_address.hook1_offset(), 16);
                write_data(pid, target_address.hook1_offset(), get_abs_jmp(inject_lib_offset.bridge1_offset()));

                printf("在 bridge1 結尾執行原本指令並跳回 main\n");
                write_data(pid, inject_lib_offset.bridge1_trampoline(), read_bytes);
                write_data(pid, inject_lib_offset.bridge1_trampoline() + 0x10, get_abs_jmp(target_address.hook1_end_offset()));
                // 失敗原因:
                //     1. 難以模擬被蓋掉的 code, 因為有 rip, call 等等跟 rip 強烈相關的 code, 除非用 capstone 分析和修改指令, 但非常麻煩
                //     2. jmp 指令太長, main 結尾的 jmp 是為了 loop, 但是被我的 jmp 蓋掉了, 最後崩潰
            } else {
                printf("等待 wait 錯誤 2\n");    
            }
        } else {
            printf("等待 wait 錯誤 1\n");
        
        }
        
        ptrace(PTRACE_DETACH, pid, NULL, SIGSTOP);
        printf("停止控制\n");
        while (true) {
            sleep(1);
        }
        
    }
    return 0;
}

/*
主程式 (PID: 100)
      |
      | 執行 fork()
      |--------------------------+
      |                          |
[父行程 (PID: 100)]         [子行程 (PID: 101)]
回傳值 pid = 101             回傳值 pid = 0
      |                          |
   (pid != 0)                 (pid == 0)
      |                          |
 進入 else 區塊             進入 if 區塊
      |                          |
 我是控制者，負責：          我是受害者，負責：
 1. waitpid() 等待          1. ptrace(TRACEME) 舉手投降
 2. 操作 ptrace             2. execl() 變身成 ELF
*/