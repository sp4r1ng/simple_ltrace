#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>
#include "ltrace.h"

enum LogLevel { L_ERROR };
void log_(LogLevel level, const std::string& message) {
    std::cerr << (level == L_ERROR ? "[ERROR] " : "") << message << std::endl;
}

void ltrace(const std::string& filename, char** argv) {
    pid_t pid = fork();

    if (pid == -1) {
        log_(L_ERROR, "Error happened while fork()");
        throw std::runtime_error("Fork failed");
    }

    if (pid == 0) { // Child process
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            log_(L_ERROR, "Error on PTRACE_TRACEME");
            std::exit(1);
        }
        execvp(filename.c_str(), argv + 1);
        log_(L_ERROR, "Error on execvp");
        std::exit(1);
    }

    int status;
    if (waitpid(pid, &status, 0) == -1) {
        log_(L_ERROR, "Error on initial waitpid");
        throw std::runtime_error("Waitpid failed");
    }

    if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_EXITKILL) == -1) {
        log_(L_ERROR, "Error on PTRACE_SETOPTIONS");
        throw std::runtime_error("PTRACE_SETOPTIONS failed");
    }

    while (true) {
        if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) {
            log_(L_ERROR, "Error on ptrace syscall (entry)");
            break;
        }
        if (waitpid(pid, &status, 0) == -1) {
            log_(L_ERROR, "Error on waitpid (entry)");
            break;
        }

        if (WIFEXITED(status)) {
            std::cout << "Process exited with status " << WEXITSTATUS(status) << std::endl;
            break;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
            log_(L_ERROR, "Error on PTRACE_GETREGS");
            break;
        }

        if (regs.orig_rax < syscall_name.size()) {
            std::cout << syscall_name[regs.orig_rax] << "()" << std::endl;
        } else {
            std::cout << std::hex << regs.orig_rax << std::endl;
        }

        if (regs.orig_rax == 231) {
            std::cout << "Process called exit_group" << std::endl;
            break;
        }

        if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) {
            log_(L_ERROR, "Error on ptrace syscall (exit)");
            break;
        }
        if (waitpid(pid, &status, 0) == -1) {
            log_(L_ERROR, "Error on waitpid (exit)");
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <file>" << std::endl;
        return 1;
    }
    try {
        ltrace(argv[1], argv);
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}