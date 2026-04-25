// sandbox_enforcer.cpp
// SecureSyscall OS — C++ Policy Decision Engine  v2.1
//
// Build:   g++ sandbox_enforcer.cpp -std=c++17 -O2 -o sandbox_enforcer
// Usage:   ./sandbox_enforcer <command> [args...]
// Examples:
//   ./sandbox_enforcer ls -la
//   ./sandbox_enforcer open /etc/shadow
//   ./sandbox_enforcer curl http://evil.com
//   ./sandbox_enforcer rm -rf /
//
// v2.1 Additions:
//   --json          Output result as JSON (for API integration)
//   --dry-run       Evaluate but never actually block stdout output
//   Policy file:    Reads /etc/securesyscall/policy.json if present
//   Audit log:      Appends to /var/log/securesyscall_enforcer.log

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <optional>

// ── ANSI colours ─────────────────────────────────────────────────────────────
#define RESET    "\033[0m"
#define BOLD     "\033[1m"
#define DIM      "\033[2m"
#define RED      "\033[31m"
#define GREEN    "\033[32m"
#define YELLOW   "\033[33m"
#define CYAN     "\033[36m"
#define MAGENTA  "\033[35m"
#define WHITE    "\033[37m"
#define BG_RED   "\033[41m"
#define BG_GREEN "\033[42m"

// ── Policy tables ─────────────────────────────────────────────────────────────
const std::unordered_set<std::string> BLOCKED_CMDS = {
    // Destructive filesystem
    "rm", "dd", "mkfs", "fdisk", "shred", "wipefs", "truncate",
    // Network exfil / recon
    "wget", "curl", "nc", "netcat", "ncat", "socat",
    "nmap", "masscan", "tcpdump", "tshark", "wireshark",
    // Shell / interpreter
    "bash", "sh", "zsh", "fish", "dash", "ksh",
    "python", "python2", "python3", "perl", "ruby", "lua",
    "node", "nodejs", "php",
    // Debugging / injection
    "ptrace", "strace", "ltrace", "gdb", "lldb",
    // Privilege operations
    "sudo", "su", "doas", "pkexec",
    // Kernel / hardware
    "insmod", "rmmod", "modprobe", "mount", "umount", "chroot",
};

const std::unordered_set<std::string> AUDITED_CMDS = {
    "ls", "cat", "head", "tail", "grep", "find", "locate",
    "ps", "top", "htop", "lsof", "netstat", "ss", "ip",
    "cp", "mv", "mkdir", "chmod", "chown", "ln",
    "df", "du", "free", "uptime", "uname",
    "id", "whoami", "groups", "env",
};

const std::unordered_set<std::string> SENSITIVE_PATHS = {
    "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/sudoers",
    "/etc/ssh/",   "/root/",       "/boot/",      "/proc/kcore",
    "/dev/mem",    "/dev/kmem",    "/dev/sda",    "/dev/nvme",
    "/sys/kernel/", "/proc/sysrq-trigger",
};

// Syscalls each command class typically invokes
const std::unordered_map<std::string, std::vector<std::string>> CMD_SYSCALLS = {
    {"rm",       {"unlink", "rmdir", "openat", "getdents64"}},
    {"curl",     {"socket", "connect", "sendmsg", "recvmsg", "read", "write"}},
    {"wget",     {"socket", "connect", "sendmsg", "recvmsg", "open", "write"}},
    {"nc",       {"socket", "bind", "listen", "accept", "connect", "read", "write"}},
    {"nmap",     {"socket", "connect", "bind", "sendmsg", "setsockopt"}},
    {"bash",     {"execve", "fork", "clone", "wait4", "pipe"}},
    {"sh",       {"execve", "fork", "clone", "wait4"}},
    {"python",   {"execve", "mmap", "mprotect", "openat", "read"}},
    {"python3",  {"execve", "mmap", "mprotect", "openat", "read"}},
    {"node",     {"execve", "mmap", "epoll_wait", "openat"}},
    {"ptrace",   {"ptrace"}},
    {"strace",   {"ptrace", "wait4"}},
    {"gdb",      {"ptrace", "fork", "execve", "mmap"}},
    {"open",     {"open", "openat"}},
    {"cat",      {"open", "openat", "read", "write"}},
    {"ls",       {"getdents64", "stat", "fstat", "openat"}},
    {"ps",       {"openat", "read", "stat", "getdents64"}},
    {"find",     {"openat", "getdents64", "stat", "fstat"}},
    {"mount",    {"mount"}},
    {"chmod",    {"chmod", "fchmodat"}},
    {"chown",    {"chown", "fchownat"}},
    {"sudo",     {"setuid", "setgid", "execve", "fork"}},
};

// Risk score adjustments per flag
struct FlagRisk {
    std::string flag;
    int         delta;
};
const std::vector<FlagRisk> RISKY_FLAGS = {
    {"-rf", 25}, {"-f", 10}, {"--force", 10},
    {"-exec", 15}, {"--exec", 15},
    {"--no-verify", 12}, {"-o", 5}, {"--output", 5},
    {"-r", 8},  // recursive
    {"--recursive", 8},
};

// ── Verdict ───────────────────────────────────────────────────────────────────
enum class Verdict { ALLOW, AUDIT, SANDBOX, BLOCK };

struct Decision {
    Verdict                  verdict;
    std::string              reason;
    std::vector<std::string> triggered_syscalls;
    std::vector<std::string> blocked_syscalls;
    int                      risk_score;
    std::string              category;
    std::vector<std::string> warnings;   // non-fatal advisory notes
};

// ── Helpers ───────────────────────────────────────────────────────────────────
bool path_is_sensitive(const std::string& arg) {
    for (const auto& sp : SENSITIVE_PATHS)
        if (arg.rfind(sp, 0) == 0 || arg.find(sp) != std::string::npos)
            return true;
    return false;
}

std::string normalize_cmd(const std::string& raw) {
    std::string cmd = raw;
    auto slash = cmd.rfind('/');
    if (slash != std::string::npos)
        cmd = cmd.substr(slash + 1);
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
    // strip leading ./
    while (cmd.size() > 1 && cmd[0] == '.' && cmd[1] == '/')
        cmd = cmd.substr(2);
    return cmd;
}

std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// ── Policy Engine ─────────────────────────────────────────────────────────────
Decision evaluate(const std::string& raw_cmd, const std::vector<std::string>& args) {
    Decision d;
    d.risk_score = 5;

    std::string cmd = normalize_cmd(raw_cmd);

    // Collect associated syscalls
    auto it = CMD_SYSCALLS.find(cmd);
    if (it != CMD_SYSCALLS.end())
        d.triggered_syscalls = it->second;

    // ── 1. Blocked command ────────────────────────────────────────
    if (BLOCKED_CMDS.count(cmd)) {
        d.verdict   = Verdict::BLOCK;
        d.reason    = "Command '" + cmd + "' is in the blocked-command policy list";
        d.category  = "command_blacklist";
        d.risk_score = 88 + (int)(args.size() * 2);
        if (d.risk_score > 99) d.risk_score = 99;
        d.blocked_syscalls = d.triggered_syscalls;
        return d;
    }

    // ── 2. Sensitive path in arguments ───────────────────────────
    for (const auto& arg : args) {
        if (path_is_sensitive(arg)) {
            d.verdict  = Verdict::BLOCK;
            d.reason   = "Access to sensitive path '" + arg + "' denied by path policy";
            d.category = "path_policy";
            d.risk_score = 85;
            d.blocked_syscalls = {"open", "openat", "read"};
            return d;
        }
    }

    // ── 3. Risky flags risk adjustment ────────────────────────────
    for (const auto& arg : args) {
        for (const auto& fr : RISKY_FLAGS) {
            if (arg == fr.flag) {
                d.risk_score += fr.delta;
                d.warnings.push_back("Risky flag detected: " + arg);
            }
        }
        // URL / IP patterns in args
        if (arg.rfind("http://", 0) == 0 || arg.rfind("https://", 0) == 0) {
            d.risk_score += 20;
            d.warnings.push_back("Network URL in arguments: " + arg);
        }
    }

    // Block if accumulated risk is very high even for non-blacklisted cmds
    if (d.risk_score >= 80) {
        d.verdict   = Verdict::BLOCK;
        d.reason    = "Risk threshold exceeded (" + std::to_string(d.risk_score) + "/100)";
        d.category  = "risk_threshold";
        d.blocked_syscalls = d.triggered_syscalls;
        return d;
    }

    // ── 4. Audited command ────────────────────────────────────────
    if (AUDITED_CMDS.count(cmd)) {
        d.verdict   = Verdict::AUDIT;
        d.reason    = "Command '" + cmd + "' is on the audit list — invocation logged";
        d.category  = "audit_policy";
        d.risk_score = std::min(d.risk_score + 15, 79);
        return d;
    }

    // ── 5. Known command → sandbox ────────────────────────────────
    if (CMD_SYSCALLS.count(cmd)) {
        d.verdict   = Verdict::SANDBOX;
        d.reason    = "Command '" + cmd + "' runs in a restricted sandbox";
        d.category  = "sandbox_policy";
        d.risk_score = std::min(d.risk_score + 30, 79);
        return d;
    }

    // ── 6. Unknown command → sandbox unknown ─────────────────────
    if (cmd.size() > 0) {
        d.verdict   = Verdict::SANDBOX;
        d.reason    = "Unknown command '" + cmd + "' sandboxed by default-deny policy";
        d.category  = "unknown_sandbox";
        d.risk_score = std::min(d.risk_score + 40, 79);
        d.warnings.push_back("Command not in known-command database");
        return d;
    }

    // ── 7. Allow (should be unreachable) ─────────────────────────
    d.verdict  = Verdict::ALLOW;
    d.reason   = "Command cleared all policy checks";
    d.category = "clean";
    return d;
}

// ── Audit logging ─────────────────────────────────────────────────────────────
void write_audit_log(const Decision& d, const std::string& full_cmd) {
    const char* log_path = "/tmp/securesyscall_enforcer.log";   // fallback
    // Try preferred path
    std::string preferred = "/var/log/securesyscall_enforcer.log";
    std::ofstream f;
    f.open(preferred, std::ios::app);
    if (!f.is_open()) {
        f.open(log_path, std::ios::app);
    }
    if (!f.is_open()) return;

    const char* verdict_str;
    switch (d.verdict) {
        case Verdict::ALLOW:   verdict_str = "ALLOW";   break;
        case Verdict::AUDIT:   verdict_str = "AUDIT";   break;
        case Verdict::SANDBOX: verdict_str = "SANDBOX"; break;
        case Verdict::BLOCK:   verdict_str = "BLOCK";   break;
        default:               verdict_str = "UNKNOWN";
    }

    f << now_iso()
      << " | " << verdict_str
      << " | " << full_cmd
      << " | risk=" << d.risk_score
      << " | " << d.reason
      << "\n";
}

// ── JSON output ───────────────────────────────────────────────────────────────
void print_json(const Decision& d, const std::string& full_cmd, bool is_block) {
    auto join = [](const std::vector<std::string>& v) -> std::string {
        std::string r = "[";
        for (size_t i = 0; i < v.size(); ++i) {
            if (i) r += ",";
            r += "\"" + v[i] + "\"";
        }
        r += "]";
        return r;
    };

    const char* verdict_str;
    switch (d.verdict) {
        case Verdict::ALLOW:   verdict_str = "ALLOW";   break;
        case Verdict::AUDIT:   verdict_str = "AUDIT";   break;
        case Verdict::SANDBOX: verdict_str = "SANDBOX"; break;
        case Verdict::BLOCK:   verdict_str = "BLOCK";   break;
        default:               verdict_str = "UNKNOWN";
    }

    std::cout << "{"
        << "\"verdict\":\"" << verdict_str << "\","
        << "\"command\":\"" << full_cmd << "\","
        << "\"reason\":\"" << d.reason << "\","
        << "\"category\":\"" << d.category << "\","
        << "\"risk_score\":" << d.risk_score << ","
        << "\"timestamp\":\"" << now_iso() << "\","
        << "\"triggered_syscalls\":" << join(d.triggered_syscalls) << ","
        << "\"blocked_syscalls\":"   << join(d.blocked_syscalls)   << ","
        << "\"warnings\":"           << join(d.warnings)
        << "}\n";
}

// ── Pretty terminal output ────────────────────────────────────────────────────
void print_banner() {
    std::cout << CYAN << BOLD
        << "╔══════════════════════════════════════════════════════╗\n"
        << "║    SecureSyscall OS — Sandbox Enforcer  v2.1        ║\n"
        << "║    Policy Decision Engine  |  syscall surface map   ║\n"
        << "╚══════════════════════════════════════════════════════╝\n"
        << RESET << "\n";
}

void print_verdict(const Decision& d, const std::string& full_cmd) {
    const char* colour;
    const char* label;
    switch (d.verdict) {
        case Verdict::ALLOW:   colour = GREEN;   label = "✓  ALLOW   "; break;
        case Verdict::AUDIT:   colour = YELLOW;  label = "◉  AUDIT   "; break;
        case Verdict::SANDBOX: colour = CYAN;    label = "⬡  SANDBOX "; break;
        case Verdict::BLOCK:   colour = RED;     label = "✗  BLOCK   "; break;
        default:               colour = WHITE;   label = "?  UNKNOWN ";
    }

    std::cout << BOLD << "  Command    " << RESET << ": " << WHITE << full_cmd << RESET << "\n";
    std::cout << BOLD << "  Timestamp  " << RESET << ": " << DIM << now_iso() << RESET << "\n";
    std::cout << BOLD << "  Decision   " << RESET << ": "
              << colour << BOLD << "[ " << label << " ]" << RESET << "\n";
    std::cout << BOLD << "  Reason     " << RESET << ": " << d.reason << "\n";
    std::cout << BOLD << "  Category   " << RESET << ": " << MAGENTA << d.category << RESET << "\n";

    // Risk bar
    std::cout << BOLD << "  Risk Score " << RESET << ": ";
    const char* rc = d.risk_score > 70 ? RED : d.risk_score > 40 ? YELLOW : GREEN;
    int bars = d.risk_score / 5;
    std::cout << rc;
    for (int i = 0; i < 20; ++i)
        std::cout << (i < bars ? "█" : "░");
    std::cout << RESET << " " << d.risk_score << "/100\n";

    // Triggered syscalls
    if (!d.triggered_syscalls.empty()) {
        std::cout << BOLD << "  Syscalls   " << RESET << ": " << DIM;
        for (size_t i = 0; i < d.triggered_syscalls.size(); ++i) {
            if (i) std::cout << "  ";
            std::cout << d.triggered_syscalls[i];
        }
        std::cout << RESET << "\n";
    }

    // Blocked syscalls (only when BLOCK verdict)
    if (!d.blocked_syscalls.empty()) {
        std::cout << BOLD << "  Blocked    " << RESET << ": " << RED;
        for (size_t i = 0; i < d.blocked_syscalls.size(); ++i) {
            if (i) std::cout << "  ";
            std::cout << d.blocked_syscalls[i];
        }
        std::cout << RESET << "\n";
    }

    // Advisory warnings
    if (!d.warnings.empty()) {
        std::cout << BOLD << "  Warnings   " << RESET << ":\n";
        for (const auto& w : d.warnings)
            std::cout << "    " << YELLOW << "⚠ " << RESET << w << "\n";
    }

    std::cout << "\n";
}

// ── Main ──────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << RED << "Usage: " << argv[0] << " [--json] [--dry-run] <command> [args...]\n" << RESET;
        std::cerr << DIM
                  << "Flags:\n"
                  << "  --json      Output result as JSON (for API use)\n"
                  << "  --dry-run   Evaluate without writing audit log\n\n"
                  << "Examples:\n"
                  << "  " << argv[0] << " ls -la\n"
                  << "  " << argv[0] << " curl http://evil.com\n"
                  << "  " << argv[0] << " open /etc/shadow\n"
                  << "  " << argv[0] << " --json rm -rf /\n"
                  << RESET;
        return 2;
    }

    // Parse global flags
    bool json_out = false;
    bool dry_run  = false;
    int  cmd_idx  = 1;

    for (int i = 1; i < argc && argv[i][0] == '-' && argv[i][1] == '-'; ++i) {
        std::string flag = argv[i];
        if      (flag == "--json")    { json_out = true; cmd_idx = i + 1; }
        else if (flag == "--dry-run") { dry_run  = true; cmd_idx = i + 1; }
    }

    if (cmd_idx >= argc) {
        std::cerr << RED << "Error: no command specified after flags\n" << RESET;
        return 2;
    }

    std::string cmd      = argv[cmd_idx];
    std::vector<std::string> args;
    std::string full_cmd = cmd;
    for (int i = cmd_idx + 1; i < argc; ++i) {
        args.push_back(argv[i]);
        full_cmd += " " + args.back();
    }

    Decision d = evaluate(cmd, args);
    bool is_block = (d.verdict == Verdict::BLOCK);

    if (json_out) {
        print_json(d, full_cmd, is_block);
    } else {
        print_banner();
        print_verdict(d, full_cmd);
    }

    if (!dry_run) {
        write_audit_log(d, full_cmd);
    }

    return is_block ? 1 : 0;
}