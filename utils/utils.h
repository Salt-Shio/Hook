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

u_int64_t get_module_base(pid_t pid, const std::string& module_keyword);

std::vector<u_int8_t> read_data(pid_t pid, u_int64_t address, int read_length);

void write_data(pid_t pid, u_int64_t address, std::vector<u_int8_t> write_bytes);

std::vector<u_int8_t> get_abs_jmp(u_int64_t abs_addr);

std::vector<u_int8_t> get_rel_jmp(u_int32_t from_addr, u_int32_t target_addr);