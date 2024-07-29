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
#include <utility>

class Utilities {
public:
    static std::vector<uint8_t> string_to_bytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            const auto byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    static std::pair<cs_insn*, size_t> disassemble(
        const std::vector<uint8_t>& code, const long address,
        const int number_of_instructions_to_disassemble) {

        csh handle;
        cs_insn *insn;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            std::cerr << "Failed to initialize Capstone" << std::endl;
            return { nullptr, 0 };
        }

        const auto count = cs_disasm(handle, code.data(), code.size(), address,
                                     number_of_instructions_to_disassemble, &insn);
        if (count > 0) {
            // TODO: Free insn. Unique_ptr???
            // cs_free(insn, count);
            cs_close(&handle);
            return { insn, count };
        }
        std::cerr << "Failed to disassemble given code!" << std::endl;
        return { nullptr, 0 };
    }

    static long swapBytes64(long value) {
        return ((((value) & 0xff00000000000000l) >> 56) |
                    (((value) & 0x00ff000000000000l) >> 40) |
                    (((value) & 0x0000ff0000000000l) >> 24) |
                    (((value) & 0x000000ff00000000l) >> 8 ) |
                    (((value) & 0x00000000ff000000l) << 8 ) |
                    (((value) & 0x0000000000ff0000l) << 24) |
                    (((value) & 0x000000000000ff00l) << 40) |
                    (((value) & 0x00000000000000ffl) << 56));
    }
};

class Debugger {
    struct Breakpoint {
        long addr = 0;
        long orig_data = 0;
    };

    Debugger() = default;

    long child_process_return_address = 0;
    pid_t child_pid = 0;
    int child_status = 0;
    std::vector<Breakpoint> break_points;
    constexpr size_t max_instruction_size = 15;
    constexpr size_t number_of_instructions_to_show = 20;

    enum class UserCommands {
        SetBreakPoint,
        ContinueExecution,
        StepOut,
        StepIn,
        StepOver,
        ShowBreakPoints,
        InvalidCommand
    };

    void print_near_code() {
        const auto [instructions, number_of_read_instr] = Utilities::disassemble(
            get_next_instructions(number_of_instructions_to_show), get_RIP(),
            number_of_instructions_to_show);

        if(instructions == nullptr) {
            return;
        }

        for (size_t i = 0; i < number_of_read_instr; i++) {
            std::cout << "0x" << std::hex << instructions[i].address << ":\t";
            std::cout << instructions[i].mnemonic << "\t" << instructions[i].op_str << std::endl;
        }
    }

    unsigned long long get_RIP() {
        user_regs_struct regs {};
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        return regs.rip;
    }

    std::vector<uint8_t> get_next_instructions(const size_t max_number_of_instructions_to_read) {
        const auto rip_value = get_RIP();
        std::vector<long> rip_data;
        for(int i = 0; i < max_number_of_instructions_to_read *
                           max_instruction_size; ++i) {
            long instr = ptrace(PTRACE_PEEKTEXT, child_pid, rip_value + i * sizeof(long), 0);
            if(instr == 0) {
                break;
            }
            rip_data.emplace_back(instr);
        }

        std::ostringstream os;
        for(const auto it : rip_data) {
            os << std::hex << std::setfill('0')
               << std::setw(sizeof(long int) * 2) << Utilities::swapBytes64(it);
        }
        std::string rip_commands = os.str();
        rip_commands.erase(rip_commands.find_last_not_of('0') + 1);
        if(rip_commands.size() % 2) {
            rip_commands.push_back('0');
        }
        return Utilities::string_to_bytes(rip_commands);
    }

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

        print_near_code();
    }

    void user_set_breakpoint() {
        Breakpoint break_point;
        std::cin >> std::hex >> break_point.addr;

        create_breakpoint(break_point);
    }

    int continue_func() {
        ptrace(PTRACE_CONT, child_pid, 0, 0);
        wait(&child_status);

        if(!is_child_process_alive()) {
            return 1;
        }
        await_breakpoint();

        return 0;
    }

    int step_out() {
        user_regs_struct regs {};
        ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
        const auto return_address = ptrace(PTRACE_PEEKDATA, child_pid, regs.rsp, nullptr);

        if(return_address != child_process_return_address) {
            Breakpoint temp_break_point;
            temp_break_point.addr = return_address;

            create_breakpoint(temp_break_point);
        }

        return continue_func();
    }

    int step_in() {
        if (ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) < 0) {
            std::cerr << "Can't execute single step. Exit..." << std::endl;
            return 1;
        }
        wait(&child_status);

        if(!is_child_process_alive()) {
            return 1;
        }

        print_near_code();
        return 0;
    }

    int step_over() {
        // Need to verify that the next instruction in call.
        // Otherwise we could have an issue (e.g. with jmp's)
        const auto [next_instruction_info, n] =
            Utilities::disassemble(get_next_instructions(1), get_RIP(), 1);

        if(next_instruction_info == nullptr) {
            std::cout << "Step over is canceled" << std::endl;
            return 0;
        }

        if(std::strcmp(next_instruction_info[0].mnemonic, "call") == 0) {
            user_regs_struct regs {};
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

            Breakpoint break_point;
            break_point.addr = regs.rip + next_instruction_info[0].size;

            create_breakpoint(break_point);
            break_points.emplace_back(break_point);

            return continue_func();
        }

        return step_in();
    }

    void show_breakpoints() {
        std::cout << "List of breakpoints: " << std::endl;
        for(const auto&[addr, orig_data] : break_points) {
            std::cout << "Address: " << std::hex << addr << std::endl;
        }
    }

    bool is_child_process_alive() {
        return !(WIFEXITED(child_status) || WIFSIGNALED(child_status));
    }

public:
    static Debugger instance(const pid_t child_pid) {
        static Debugger debugger;
        debugger.child_pid = child_pid;
        return debugger;
    }

    void run() {
        wait(&child_status);
        if(!is_child_process_alive()) {
            std::cout << "Child process wasn't started. Nothing to debug" << std::endl;
            return;
        }

        // For step_out
        define_child_process_return_address();

        print_near_code();

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
                        return;
                    }
                    break;
                }
                case UserCommands::StepOut : {
                    if(step_out()) {
                        return;
                    }
                    break;
                }
                case UserCommands::StepIn : {
                    if(step_in()) {
                        return;
                    }
                    break;
                }
                // Should work only for call asm instruction
                case UserCommands::StepOver : {
                    if(step_over()) {
                        return;
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

void run_child(const char* target_name) {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
        std::cerr << "ptrace: Can't attach to the child process" << std::endl;
        return;
    }
    execl(target_name, target_name);
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        std::cout << "Wrong command line params. Usage: "
                  << argv[0] << " [/path/to/executable/to/debug]" << std::endl;
        return 0;
    }

    pid_t child_pid = fork();
    if (child_pid == 0) {
        run_child(argv[1]);
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