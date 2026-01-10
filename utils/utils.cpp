#include "utils.h"

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
    for (int i = 0; i < read_length; i += 8) {
        u_int8_t read_bytes[8];
        u_int64_t data_to_read = ptrace(PTRACE_PEEKTEXT, pid, address + i, NULL);
        memcpy(read_bytes, &data_to_read, 8);

        for (int j = 0; j < 8 && i + j < read_length; j++) {
            data.push_back(read_bytes[j]);
        }
    }
    return data;
}

void write_data(pid_t pid, u_int64_t address, std::vector<u_int8_t> write_bytes) {
    int write_size = write_bytes.size();
    int remain = write_size % 8;
    
    if (remain > 0) {
        std::vector<u_int8_t> ori_data = read_data(pid, address + write_size - remain, 8);
        for (int i = remain; i < 8; i++) {
            write_bytes.push_back(ori_data[i]);
        }
    }
    
    write_size = write_bytes.size();

    std::cout << "write_size: " << write_size << std::endl;
    for (int i = 0; i < write_size; i++) {
        printf("\\x%02x ", write_bytes[i]);
    }
    std::cout << std::endl;
    for (int i = 0; i < write_size; i += 8) {
        u_int64_t data_to_write;
        memcpy(&data_to_write, &write_bytes[i], 8);
        ptrace(PTRACE_POKETEXT, pid, address + i, data_to_write);
    }
}

std::vector<u_int8_t> get_abs_jmp(u_int64_t abs_addr) {
    std::vector<u_int8_t> code = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // abs_addr
    };
    memcpy(&code[6], &abs_addr, 8);
    return code;
}

std::vector<u_int8_t> get_rel_jmp(u_int32_t from_addr, u_int32_t target_addr) {
    std::vector<u_int8_t> code = {0xE9, 0x00, 0x00, 0x00, 0x00};
    u_int32_t offset = target_addr - (from_addr + 5);
    memcpy(&code[1], &offset, 4);

    return code;
}
