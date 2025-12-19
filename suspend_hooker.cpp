#include <vector>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

u_int64_t get_base_addr(pid_t pid, const char* module_name) {
    char filename[64];
    char line[256];
    FILE *fp;
    u_int64_t start_addr = 0;
    
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);

    fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen maps");
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        
        // 檢查是否為目標模組
        if (strstr(line, module_name)) {
            char *dash = strchr(line, '-'); // dash 指向 line 中 '-' 的位址
            if (dash) {
                *dash = '\0'; // 5be46a2bd000-5be46a2be000 ---> 5be46a2bd000\x005be46a2be000
                start_addr = strtoul(line, NULL, 16); // 5be46a2bd000\x00 --> ul(5be46a2bd000\x00)
                break; // 找到了就跳出，通常第一筆就是 Base
            }
        }
    }

    fclose(fp);
    return start_addr;
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

    if (pid == 0) { // === 子行程 (Target) ===
        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // 用 0 表示 trace 自己，這裡用 getpid 也能跑
        execl(target_elf, target_elf, NULL); // 跑起 elf，整個程式會換成 program_path 的內容
        perror("execl failed");
        exit(1);

    } else { // === 父行程 (Controller) ===
        u_int64_t offset = 0x11d6;
        int status;
        printf("pid %d\n", pid);
        waitpid(pid, &status, 0);

        if (WIFSTOPPED(status)) {
            u_int64_t base = get_base_addr(pid, &target_elf[2]);
            printf("獲取目標 base address: %lx\n", base);
            
            std::vector<u_int8_t> read_bytes;
            read_bytes = read_data(pid, base + offset, 16);
            for (u_int8_t byte : read_bytes) {
                printf("%02x ", byte);
            }
            printf("\n");

            std::vector<u_int8_t> write_bytes = get_abs_jmp(0xdeadbeefaabbccdd);
            write_data(pid, base + offset, write_bytes);
            printf("Press ENTER to detach...");
            getchar();

        } else {
            printf("Something went wrong, process didn't stop.\n");
        
        }
        
        ptrace(PTRACE_DETACH, pid, NULL, SIGSTOP);
        printf(">> Detached. Target resumes execution.\n");
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