## Simple-debugger

Simple-debugger is an instruction-level debugger with command line interface. Works only on Linux x86_64.

### Build
1. Go to the project's root directory
2. Run `sudo ./build.sh`

`./build.sh` script install all required dependecies.
The list of dependencies:
1. `Clang C/C++ compiler`
2. `CMake`
3. `Git`
4. `Capstone multi-architecture disassembly framework`
5. `Java JDK`
6. `Kotlin compiler`
7. `Gradle`

### Run
1. Go to the project's root directory
2. Run `sudo ./run.sh <path to executable to debug>`

### Supported operations
The `simple-debugger` supports the following operations:
1. `set_breakpoint [address]` - Set breakpoint at the address
2. `continue` - Executes the process until the breakpoint triggered or the end of the process
3. `step_out` - Executes the remaining code within the current function and return to the calling function
4. `step_in`  - Executes the next instruction of the process
5. `step_over` - Executes the next instruction of code but without stepping into `call` instruction
6. `bp_list` - Print the list of the set breakpoints
7. `show_state` - Print the value of the main general purpose registers
8. `help` - Print the list of available operations

### CLI Interface
The `simple-debugger` at the start of the execution prints the help information and the next 20 instructions of the process that is being debugged. The current instruction to execute is always the most top. 
Then the `simple-debugger` is waiting for the next user's command. After each command that executes child process the `simple-debugger` is printing the next 20 instructions of child process.

### How simple-debugger is implemented:
The simple-debugger consists of two separated processes: 
1. `debugger-server`
2. `debugger-client`

### How the debugger-server is implemented
The debugger-server is written using C++. The debugging works using `ptrace`. 
1. _The `debugger-server` initialization_
   
   The `debugger-server` takes the path to the program to debug via CL parameter. The debugger-server starts the child process with passed program using `fork()` and `execl()`.
   The started child process call `ptrace()` with `PTRACE_TRACEME` argument to stop the execution before the first instruction and wait for the any signals from the parent process.
   
2. _`set_breakpoint` implementation_

   To set a breakpoint `debugger-server` store and replace the first byte value at the passed address with the `CC`. `CC` is an `int 3` instruction (_trap to debugger_).
   When this instruction with be reached later (breakpoint is triggered) the `debugger-server` restore the value by the address with the initial value.

3. _`continue` implementation_

   The `ptrace()` call with `PTRACE_CONT` argument.

4. _`step_out` implementation_

   The `debugger-server` reads the current value of the `rsp` register using `ptrace()` with `PTRACE_GETREGS` argument. `rsp` register points to the function's return address. Then the `debugger-server` set a breakpoint at this address and continue the child process execution.

5. _`step_in` implementation_

   The `ptrace()` call with `PTRACE_SINGLESTEP` argument.
    
6. _`step_over` implementation_

   The `debugger-server` reads and disassemble the next instruction. If the next instruction is "call" then the `debugger-server` set breakpoint at the next after "call" instruction and continue child process execution. Otherwise call `step_in`. 
   
### How debugger-client is implemented
The debugger-client is written in Kotlin. The debugger-client is a simple wrapper around debugger-server. It is assumed that users will interact with `simple-debugger` via `debugger-client`.

The `debugger-client` runs the `debugger-server` process and two coroutines with IO dispatcher to interact with debugger-server. 

1. `readJob` coroutine - Async read all data from the standard output of the debugger-server
2. `writeJob` coroutine - Async write the user's commands to the debugger-server

The synchronization between coroutines is implemented using `Kotlin Channels`
