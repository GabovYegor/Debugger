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

cs_insn get_next_instruction_info(pid_t child_pid) {
    long address = 0;
    return disassemble_one_instruction(hexStringToBytes(get_RIP_data(child_pid, address)));
}

void print_near_code(pid_t child_pid) {
    long address = 0;
    const auto code = hexStringToBytes(get_RIP_data(child_pid, address));
    disassemble(code, address);
}

class Printer {

};



class Debugger {
    struct Breakpoint {
        long addr = 0;
        long orig_data = 0;
    };

    Debugger() = default;

    long child_process_return_address = 0;
    pid_t child_pid = 0;
    int wait_status = 0;
    std::vector<Breakpoint> break_points;

    enum class UserCommands {
        SetBreakPoint,
        ContinueExecution,
        StepOut,
        StepIn,
        StepOver,
        ShowBreakPoints,
        InvalidCommand
    };

    UserCommands convert_user_input_to_UserCommands(const std::string& user_input) {
        if(user_input == "bp") {
            return UserCommands::SetBreakPoint;
        }
        if(user_input == "c") {
            return UserCommands::ContinueExecution;
        }
        if(user_input == "sout") {
            return UserCommands::StepOut;
        }
        if(user_input == "si") {
            return UserCommands::StepIn;
        }
        if(user_input == "so") {
            return UserCommands::StepOver;
        }
        if(user_input == "l") {
            return UserCommands::ShowBreakPoints;
        }
        return UserCommands::InvalidCommand;
    }

    void define_child_process_return_address() {
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
        child_process_return_address = ptrace(PTRACE_PEEKDATA, child_pid, (void*)regs.rsp, nullptr);
    }

    void create_breakpoint(Breakpoint breakpoint_info) {
        breakpoint_info.orig_data = ptrace(PTRACE_PEEKTEXT, child_pid, breakpoint_info.addr, 0);
        ptrace(PTRACE_POKETEXT, child_pid, breakpoint_info.addr,
            (breakpoint_info.orig_data & ~0xFF) | 0xCC);
        break_points.emplace_back(breakpoint_info);
    }

    void remove_breakpoint(pid_t child_pid, Breakpoint breakpoint_info) {
        ptrace(PTRACE_POKETEXT, child_pid, breakpoint_info.addr);
    }

    void await_breakpoint() {
        // Breakpoint was triggered
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        --regs.rip;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        const auto bp_to_remove = std::find_if(break_points.begin(), break_points.end(),
            [&regs](const Breakpoint bp) {
                return regs.rip == bp.addr;
            });
        remove_breakpoint(child_pid, *bp_to_remove);
        break_points.erase(bp_to_remove);

        print_near_code(child_pid);
    }

    void user_set_breakpoint() {
        Breakpoint break_point;
        std::cout << "Input bp address: ";
        std::cin >> std::hex >> break_point.addr;

        create_breakpoint(break_point);
    }

    int continue_func() {
        ptrace(PTRACE_CONT, child_pid, 0, 0);
        wait(&wait_status);

        // TODO: Create function for this
        if(!WIFSTOPPED(wait_status))
            return 1;

        await_breakpoint();

        return 0;
    }

    int step_out() {
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
        const auto return_address = ptrace(PTRACE_PEEKDATA, child_pid, (void*)regs.rsp, nullptr);

        if(return_address != child_process_return_address) {
            Breakpoint temp_break_point;
            temp_break_point.addr = return_address;

            create_breakpoint(temp_break_point);
        }

        if(continue_func()) {
            return 1;
        }
        return 0;
    }

    int step_in() {
        if (ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) < 0) {
            std::cerr << "ptrace" << std::endl;
            return 1;
        }
        /* Wait for child to stop on its next instruction */
        wait(&wait_status);

        // TODO:
        if(!WIFSTOPPED(wait_status))
            return 1;

        print_near_code(child_pid);
        return 0;
    }

    int step_over() {
        const auto next_instruction_info = get_next_instruction_info(child_pid);

        if(next_instruction_info.mnemonic == "call") {
            user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

            Breakpoint temp_break_point;
            temp_break_point.addr = regs.rip + next_instruction_info.size;

            create_breakpoint(temp_break_point);
            break_points.emplace_back(temp_break_point);

            if(continue_func()) {
                return 1;
            }
        }
        else {
            return step_in();
        }
        return 0;
    }

    void show_breakpoints() {
        std::cout << "List of breakpoints: " << std::endl;
        for(const auto&[addr, orig_data] : break_points) {
            std::cout << "Address: " << std::hex << addr << std::endl;
        }
    }

public:
    static Debugger instance(const pid_t child_pid) {
        static Debugger debugger;
        debugger.child_pid = child_pid;
        return debugger;
    }

    int run() {
        wait(&wait_status);
        // Check wait_status value;

        define_child_process_return_address();

        print_near_code(child_pid);

        std::string user_input;

        while (true) {
            std::cin >> user_input;

            switch (convert_user_input_to_UserCommands(user_input)) {
                case UserCommands::SetBreakPoint : {
                    user_set_breakpoint();
                    break;
                }
                case UserCommands::ContinueExecution : {
                    if(continue_func()) {
                        return 1;
                    }
                    break;
                }
                case UserCommands::StepOut : {
                    if(step_out()) {
                        return 1;
                    }
                    break;
                }
                case UserCommands::StepIn : {
                    step_in();
                    break;
                }
                // Should work only for call asm instruction
                case UserCommands::StepOver : {
                    if(step_over()) {
                        return 1;
                    }
                    break;
                }
                case UserCommands::ShowBreakPoints : {
                    show_breakpoints();
                    break;
                }
                default:
                    std::cout << "Wrong command" << std::endl;
            }
        }
    }
};

void run_target(const char* target_name) {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
        perror("ptrace");
        return;
    }

    // TODO: Do we need nullptr?
    execl(target_name, target_name, nullptr);
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        std::cout << "Wrong input" << std::endl;
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        run_target(argv[1]);
    }
    else if (child_pid > 0) {
        Debugger debugger = Debugger::instance(child_pid);
        debugger.run();
    }
    else {
        perror("fork");
        return -1;
    }

    return 0;
}