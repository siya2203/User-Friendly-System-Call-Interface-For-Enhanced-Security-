#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>

enum class Decision {
    Allow,
    Audit,
    Sandbox,
    Block
};

static std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

static std::string decision_name(Decision decision) {
    switch (decision) {
        case Decision::Allow:
            return "ALLOWED";
        case Decision::Audit:
            return "AUDITED";
        case Decision::Sandbox:
            return "SANDBOXED";
        case Decision::Block:
            return "BLOCKED";
    }
    return "BLOCKED";
}

static Decision decide(const std::string& syscall, const std::string& argument) {
    const std::string call = lower(syscall);
    const std::string arg = lower(argument);
    if (call == "ptrace" || call == "mount") {
        return Decision::Block;
    }
    if (call == "mprotect" && arg.find("prot_exec") != std::string::npos && arg.find("prot_write") != std::string::npos) {
        return Decision::Block;
    }
    if ((call == "open" || call == "openat") && (arg.find("/etc/shadow") != std::string::npos || arg.find("/proc/mem") != std::string::npos)) {
        return Decision::Block;
    }
    if (call == "execve" || call == "fork" || call == "clone" || call == "mmap") {
        return Decision::Sandbox;
    }
    if (call == "socket" || call == "connect" || call == "sendto" || call == "recvfrom" || call == "setuid") {
        return Decision::Audit;
    }
    return Decision::Allow;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "usage: sandbox_enforcer <syscall> [argument...]\n";
        return 1;
    }
    std::string syscall = argv[1];
    std::string argument;
    for (int i = 2; i < argc; ++i) {
        argument += argv[i];
        if (i + 1 < argc) {
            argument += " ";
        }
    }
    Decision decision = decide(syscall, argument);
    std::cout << decision_name(decision) << "\n";
    return decision == Decision::Block ? 2 : 0;
}
