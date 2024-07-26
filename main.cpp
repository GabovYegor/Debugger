#include <boost/process.hpp>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace bp = boost::process;

int main(int argc, char* argv[]) {
    // Создаем процесс с помощью Boost.Process
    bp::child c(argv[1]);

    pid_t pid = c.id();
    std::cout << "Created process with PID: " << pid << std::endl;

    // Используем ptrace для управления процессом
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
        std::cerr << "ptrace(PTRACE_ATTACH) failed: " << strerror(errno) << std::endl;
        return 1;
    }

    std::cout << "Successfully attached to process with PID: " << pid << std::endl;

    // Ожидаем, пока процесс остановится
    int status;
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status)) {
        std::cout << "Process stopped, sending PTRACE_CONT" << std::endl;
        ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    }

    // Ожидаем завершения процесса
    c.wait();
    if (c.exit_code() == 0) {
        std::cout << "Command executed successfully" << std::endl;
    } else {
        std::cout << "Command failed with exit code: " << c.exit_code() << std::endl;
    }

    return 0;
}
