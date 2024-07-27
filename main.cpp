#include <cstring>
#include <iomanip>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <capstone/capstone.h>

constexpr size_t max_instruction_size = 15;
constexpr size_t number_of_instructions_to_show = 20;

std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

cs_insn disassemble_one_instruction(const std::vector<uint8_t>& code) {
    csh handle;
    cs_insn *insn;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cerr << "Failed to initialize Capstone" << std::endl;
    }

    size_t count = cs_disasm(handle, code.data(), code.size(), 0x1, 1, &insn);
    if (count > 0) {
        cs_close(&handle);
        return insn[0];
    }
    std::cerr << "Failed to disassemble given code!" << std::endl;
}

void disassemble(const std::vector<uint8_t>& code, const long address) {
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cerr << "Failed to initialize Capstone" << std::endl;
        return;
    }

    count = cs_disasm(handle, code.data(),
                      code.size(), address, number_of_instructions_to_show, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            std::cout << "0x" << std::hex << insn[i].address << ":\t";
            std::cout << insn[i].mnemonic << "\t" << insn[i].op_str << std::endl;
        }

        cs_free(insn, count);
    } else {
        std::cerr << "Failed to disassemble given code!" << std::endl;
    }

    cs_close(&handle);
}

void run_target(const char* target_name) {
    std::cout << "Target program (" << target_name << ") is being run" << std::endl;
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        perror("ptrace");
        return;
    }

    execl(target_name, target_name, NULL);
}

long int swapBytes64(long value) {
    return ((value >> 56) & 0x00000000000000FF) |
           ((value >> 40) & 0x000000000000FF00) |
           ((value >> 24) & 0x0000000000FF0000) |
           ((value >> 8)  & 0x00000000FF000000) |
           ((value << 8)  & 0x000000FF00000000) |
           ((value << 24) & 0x0000FF0000000000) |
           ((value << 40) & 0x00FF000000000000) |
           ((value << 56) & 0xFF00000000000000);
}

struct debug_breakpoint_t {
    long addr = 0;
    long orig_data = 0;
};

std::string get_RIP_data(pid_t child_pid, long& address) {
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

    std::vector<long> rip_data;
    size_t bytes_read = 0;
    for(int i = 0; i < number_of_instructions_to_show *
                       max_instruction_size; ++i) {
        long instr = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip + i * sizeof(long), 0);
        if(instr == 0) {
            break;
        }
        rip_data.emplace_back(instr);
    }

    std::ostringstream os;
    for(const auto it : rip_data) {
        os << std::hex << std::setfill('0')
           << std::setw(sizeof(long int) * 2) << swapBytes64(it);
    }
    std::string rip_commands = os.str();
    rip_commands.erase(rip_commands.find_last_not_of('0') + 1);
    if(rip_commands.size() % 2) {
        rip_commands.push_back('0');
    }
    address = regs.rip;
    return rip_commands;
}

void print_near_code(pid_t child_pid) {
    long address = 0;
    const auto code = hexStringToBytes(get_RIP_data(child_pid, address));
    disassemble(code, address);
}

cs_insn get_one_instruction_info(pid_t child_pid) {
    long address = 0;
    return disassemble_one_instruction(hexStringToBytes(get_RIP_data(child_pid, address)));
}

void create_breakpoint(pid_t child_pid, debug_breakpoint_t& breakpoint_info) {
    breakpoint_info.orig_data = ptrace(PTRACE_PEEKTEXT, child_pid, breakpoint_info.addr, 0);
    ptrace(PTRACE_POKETEXT, child_pid, breakpoint_info.addr,
        (breakpoint_info.orig_data & ~0xFF) | 0xCC);
}

void remove_breakpoint(pid_t child_pid, debug_breakpoint_t breakpoint_info) {
    ptrace(PTRACE_POKETEXT, child_pid, breakpoint_info.addr);
}

std::vector<debug_breakpoint_t> break_points;

int continue_func(pid_t child_pid, int wait_status) {
    ptrace(PTRACE_CONT, child_pid, 0, 0);
    wait(&wait_status);

    if(!WIFSTOPPED(wait_status))
        return 1;

    // Else: Breakpoint was triggered
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    --regs.rip;
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

    std::cout << "Child stopped at the address: 0x" << std::hex << regs.rip << std::endl;
    const auto bp_to_remove = std::find_if(break_points.begin(), break_points.end(),
        [&](debug_breakpoint_t bp) {
            return regs.rip == reinterpret_cast<long>(bp.addr);
        });
    remove_breakpoint(child_pid, *bp_to_remove);
    break_points.erase(bp_to_remove);
    print_near_code(child_pid);

    return 0;
}

void run_debugger(pid_t child_pid)
{
    int wait_status;
    std::cout << "debugger start" << std::endl;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    print_near_code(child_pid);

    std::string user_command;

    while (true) {
        std::cin >> user_command;
        if(user_command == "bp") {
            debug_breakpoint_t temp_break_point;
            std::cout << "Input bp address: ";
            std::cin >> std::hex >> temp_break_point.addr;

            create_breakpoint(child_pid, temp_break_point);
            break_points.emplace_back(temp_break_point);
        }

        if(user_command == "c") {
            if(continue_func(child_pid, wait_status)) {
                break;
            }
        }

        if(user_command == "si") {
            /* Make the child execute another instruction */
            if (ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) < 0) {
                std::cerr << "ptrace" << std::endl;
                return;
            }

            /* Wait for child to stop on its next instruction */
            wait(&wait_status);
            if(!WIFSTOPPED(wait_status))
                break;

            print_near_code(child_pid);
        }

        if(user_command == "so") {
            const auto info = get_one_instruction_info(child_pid);
            std::cout << "Command: " << info.mnemonic << ", size: " << info.size << std::endl;

            user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

            debug_breakpoint_t temp_break_point;
            temp_break_point.addr = regs.rip + info.size;

            create_breakpoint(child_pid, temp_break_point);
            break_points.emplace_back(temp_break_point);

            if(continue_func(child_pid, wait_status)) {
                break;
            }
        }

        if(user_command == "l") {
            std::cout << "List of breakpoints: " << std::endl;
            for(const auto& it : break_points) {
                std::cout << "Address: " << std::hex << it.addr << std::endl;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    pid_t child_pid = fork();
    if (child_pid == 0) {
        // This is the child process
        run_target(argv[1]);
    } else if (child_pid > 0) {
        // This is the parent process
        run_debugger(child_pid);
    } else {
        perror("fork");
        return -1;
    }

    return 0;
}