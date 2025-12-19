#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>

#include <string>
#include <vector>

u_int64_t get_module_base(pid_t pid, const std::string& module_keyword) {
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;

    while (std::getline(maps, line)) {
        if (line.find(module_keyword) != std::string::npos) {
            size_t dash_pos = line.find('-');
            if (dash_pos != std::string::npos) {
                try {
                    return std::stoull(line.substr(0, dash_pos), nullptr, 16);
                } catch (...) { // for parse hex failed
                    continue;
                }
            }
        }
    }
    return 0; // 未找到
}

std::vector<u_int8_t> read_data(pid_t pid, u_int64_t address, int read_length) {
    std::vector<u_int8_t> data;
    read_length = read_length + 8 - read_length % 8;
    for (int i = 0; i < read_length; i += 8) {
        u_int8_t read_bytes[8];
        long data_to_read = ptrace(PTRACE_PEEKTEXT, pid, address + i, NULL);
        memcpy(read_bytes, &data_to_read, 8);
        for (int j = 0; j < 8; j++) {
            data.push_back(read_bytes[j]);
        }
    }
    return data;
    
}

void write_data(pid_t pid, u_int64_t address, std::vector<u_int8_t> write_bytes) {
    int write_size = write_bytes.size();
    for (int i = 0; i < write_size; i += 8) {
        u_int64_t data_to_write;
        memcpy(&data_to_write, &write_bytes[i], 8);
        if (ptrace(PTRACE_POKETEXT, pid, address + i, data_to_write) < 0) {
            perror("ptrace poke");
        } 
    }
}

std::vector<u_int8_t> get_abs_jmp(u_int64_t targetAddr) {
    std::vector<u_int8_t> code = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // targetAddr
    };
    memcpy(&code[6], &targetAddr, 8);

    int pad_len = 8 - code.size() % 8;
    for (int i = 0; i < pad_len; ++i) {
        code.push_back(0x00); 
    }
    
    return code;
}


int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("[USAGE] %s [target_elf]\n", argv[0]);
        return 0;
    }

    const char* target_elf = argv[1]; 

    pid_t pid = fork(); 
    // 這裡會分出兩個一模一樣的程式，pid != 0 這個 pid 是子進程的 pid，pid == 0 表示自己是 子行程，因此要有兩個分支

    if (pid == 0) { // Target
        setenv("LD_PRELOAD", "./inject_lib.so", 1);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // 用 0 表示 trace 自己，這裡用 getpid 應該也能跑
        execl(target_elf, target_elf, NULL); // 跑起 elf，整個程式會換成 program_path 的內容
        perror("目標執行失敗");
        exit(1);

    } else { // Controller
        u_int64_t main_offset = 0x1189;
        u_int64_t hook_address = 0x11d6;
        u_int64_t inject_offset = 0x1119;

        int status;
        printf("pid %d\n", pid);
        waitpid(pid, &status, 0);

        if (WIFSTOPPED(status)) {
            u_int64_t main_base = get_module_base(pid, &target_elf[2]);
            printf("獲取目標 main_base address: %lx\n", main_base);
            
            std::vector<u_int8_t> read_bytes;
            std::vector<u_int8_t> write_bytes;

            // stop at main (already load libc, my libc)
            read_bytes = read_data(pid, main_base + main_offset, 8);
            write_bytes.assign(read_bytes.begin(), read_bytes.end());
            write_bytes[0] = 0xCC; // INT3
            write_data(pid, main_base + main_offset, write_bytes);
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            waitpid(pid, &status, 0);

            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                u_int64_t inject_base = get_module_base(pid, "inject_lib.so");
                printf("獲取目標 inject_base address: %lx\n", inject_base);

                write_data(pid, main_base + main_offset, read_bytes); // delete INT3
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                regs.rip -= 1; 
                ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                
                printf("寫入 jmp code\n");
                auto jmp_code = get_abs_jmp(inject_base + inject_offset);
                write_data(pid, main_base + hook_address, jmp_code);
                
            } else {
                printf("等待 wait 錯誤 2\n");    
            }
        } else {
            printf("等待 wait 錯誤 1\n");
        
        }
        
        ptrace(PTRACE_DETACH, pid, NULL, SIGSTOP);
        printf("停止控制");
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