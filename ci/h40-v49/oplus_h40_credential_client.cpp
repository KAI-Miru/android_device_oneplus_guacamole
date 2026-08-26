#include "oplus_h40_credential_client.hpp"

#include "oplus_h40_credential_protocol.hpp"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include <array>
#include <climits>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>

#include "twcommon.h"

namespace twrp {
namespace oplus_h40 {
namespace {

namespace protocol = credential_protocol;

constexpr int kSetupTimeoutMs = 30000;
constexpr int kVerifyTimeoutMs = 60000;
constexpr int kExitTimeoutMs = 5000;

class ScopedFd {
  public:
    explicit ScopedFd(int fd = -1) : fd_(fd) {}
    ~ScopedFd() {
        if (fd_ >= 0) close(fd_);
    }
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    int get() const { return fd_; }
    int release() {
        const int fd = fd_;
        fd_ = -1;
        return fd;
    }

  private:
    int fd_;
};

std::uint64_t MonotonicMilliseconds() {
    struct timespec now = {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return static_cast<std::uint64_t>(now.tv_sec) * 1000ULL +
           static_cast<std::uint64_t>(now.tv_nsec) / 1000000ULL;
}

std::uint64_t MakeAttemptId() {
    static std::uint32_t sequence = 0;
    ++sequence;
    struct timespec now = {};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (static_cast<std::uint64_t>(getpid()) << 32) ^
           static_cast<std::uint64_t>(now.tv_nsec) ^
           (static_cast<std::uint64_t>(sequence) << 16);
}

bool SendPacket(int fd, const void* data, std::size_t size) {
    const ssize_t sent = send(fd, data, size, MSG_NOSIGNAL);
    return sent == static_cast<ssize_t>(size);
}

enum class ReceiveStatus {
    kPacket,
    kTimeout,
    kClosed,
    kError,
};

ReceiveStatus ReceivePacket(int fd, std::uint64_t deadline_ms,
                            std::array<std::uint8_t, sizeof(protocol::CrashFrame)>* packet,
                            std::size_t* packet_size) {
    while (true) {
        const std::uint64_t now = MonotonicMilliseconds();
        if (now >= deadline_ms) return ReceiveStatus::kTimeout;
        const std::uint64_t remaining = deadline_ms - now;
        const int timeout = remaining > static_cast<std::uint64_t>(INT_MAX)
                                ? INT_MAX
                                : static_cast<int>(remaining);

        struct pollfd descriptor = {};
        descriptor.fd = fd;
        descriptor.events = POLLIN | POLLHUP | POLLERR;
        const int poll_result = poll(&descriptor, 1, timeout);
        if (poll_result < 0) {
            if (errno == EINTR) continue;
            return ReceiveStatus::kError;
        }
        if (poll_result == 0) return ReceiveStatus::kTimeout;
        if ((descriptor.revents & POLLIN) != 0) {
            const ssize_t received = recv(fd, packet->data(), packet->size(), MSG_TRUNC);
            if (received < 0) {
                if (errno == EINTR) continue;
                return ReceiveStatus::kError;
            }
            if (received == 0) return ReceiveStatus::kClosed;
            *packet_size = static_cast<std::size_t>(received);
            return ReceiveStatus::kPacket;
        }
        if ((descriptor.revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            return ReceiveStatus::kClosed;
        }
    }
}

bool ValidateHeader(const protocol::FrameHeader& header, std::size_t packet_size,
                    std::uint64_t attempt_id) {
    return header.magic == protocol::kMagic && header.version == protocol::kVersion &&
           header.frame_size == packet_size && header.reserved == 0 &&
           header.attempt_id == attempt_id;
}

bool WaitForChild(pid_t pid, int timeout_ms, int* status) {
    const std::uint64_t deadline = MonotonicMilliseconds() + timeout_ms;
    while (MonotonicMilliseconds() < deadline) {
        const pid_t waited = waitpid(pid, status, WNOHANG);
        if (waited == pid) return true;
        if (waited < 0 && errno != EINTR) return false;
        usleep(20000);
    }
    return false;
}

void KillAndReap(pid_t pid) {
    if (pid <= 0) return;
    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
        LOGERR("[H40 V49 HELPER] failed to kill helper pid=%d: %s\n", pid,
               strerror(errno));
    }
    int status = 0;
    if (!WaitForChild(pid, kExitTimeoutMs, &status)) {
        LOGERR("[H40 V49 HELPER] helper pid=%d did not reap after SIGKILL; "
               "continuing in fatal adapter state\n",
               pid);
    }
}

bool SaveHelperMaps(pid_t pid, std::uint64_t attempt_id) {
    const std::string source = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream input(source);
    std::ofstream output("/tmp/h40-credential-helper.maps", std::ios::trunc);
    if (!input.is_open() || !output.is_open()) {
        LOGERR("[H40 V49 HELPER] unable to save helper maps for attempt=%llu\n",
               static_cast<unsigned long long>(attempt_id));
        return false;
    }
    output << "attempt=" << attempt_id << " pid=" << pid << "\n";
    bool saw_oem = false;
    bool saw_stock_libcxx = false;
    bool saw_helper = false;
    bool saw_private_runtime = false;
    std::string line;
    while (std::getline(input, line)) {
        output << line << "\n";
        saw_oem = saw_oem ||
                  line.find("/system/lib64/libdecrypt_recovery.so") != std::string::npos;
        saw_stock_libcxx = saw_stock_libcxx ||
                          line.find("/system/lib64/libc++.so") != std::string::npos;
        saw_helper = saw_helper ||
                     line.find("/system/bin/oplus_h40_credential_helper") !=
                             std::string::npos;
        saw_private_runtime = saw_private_runtime ||
                              line.find("/system/tw/") != std::string::npos;
    }
    output.flush();
    if (!saw_oem || !saw_stock_libcxx || !saw_helper || saw_private_runtime) {
        LOGERR("[H40 V49 HELPER] stock namespace proof failed attempt=%llu "
               "helper=%d oem=%d stockLibcxx=%d privateRuntime=%d\n",
               static_cast<unsigned long long>(attempt_id), saw_helper, saw_oem,
               saw_stock_libcxx, saw_private_runtime);
        return false;
    }
    LOGINFO("[H40 V49 HELPER] saved stock-runtime maps for attempt=%llu pid=%d\n",
            static_cast<unsigned long long>(attempt_id), pid);
    return true;
}

bool AddressInSavedOemMapping(std::uint64_t address) {
    std::ifstream maps("/tmp/h40-credential-helper.maps");
    if (!maps.is_open()) return false;
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("/system/lib64/libdecrypt_recovery.so") == std::string::npos) {
            continue;
        }
        unsigned long long start = 0;
        unsigned long long end = 0;
        if (std::sscanf(line.c_str(), "%llx-%llx", &start, &end) == 2 &&
            address >= start && address < end) {
            return true;
        }
    }
    return false;
}

void SaveCrashReport(const protocol::CrashFrame& crash, pid_t pid) {
    const bool pc_in_oem = crash.program_counter >= crash.oem_load_base &&
                           AddressInSavedOemMapping(crash.program_counter);
    const std::uint64_t pc_offset =
            pc_in_oem ? crash.program_counter - crash.oem_load_base : 0;
    const std::uint64_t lr = crash.registers[30];
    const bool lr_in_oem = lr >= crash.oem_load_base && AddressInSavedOemMapping(lr);
    const std::uint64_t lr_offset = lr_in_oem ? lr - crash.oem_load_base : 0;

    LOGERR("[H40 V49 CRASH] helper pid=%d tid=%u signal=%d code=%d stage=%u "
           "fault=0x%llx pc=0x%llx pcInOem=%d pcOffset=0x%llx "
           "lr=0x%llx lrInOem=%d lrOffset=0x%llx sp=0x%llx\n",
           pid, crash.crashing_tid, crash.signal_number, crash.signal_code, crash.stage,
           static_cast<unsigned long long>(crash.fault_address),
           static_cast<unsigned long long>(crash.program_counter),
           pc_in_oem,
           static_cast<unsigned long long>(pc_offset),
           static_cast<unsigned long long>(lr),
           lr_in_oem,
           static_cast<unsigned long long>(lr_offset),
           static_cast<unsigned long long>(crash.stack_pointer));

    std::ofstream report("/tmp/h40-credential-helper-crash.txt", std::ios::trunc);
    if (!report.is_open()) return;
    report << std::hex << std::setfill('0');
    report << "attempt=" << std::dec << crash.header.attempt_id << " pid=" << pid
           << " tid=" << crash.crashing_tid
           << " signal=" << crash.signal_number << " code=" << crash.signal_code
           << " stage=" << crash.stage << "\n" << std::hex;
    report << "fault=0x" << crash.fault_address << "\n";
    report << "oem_load_base=0x" << crash.oem_load_base << "\n";
    report << "pc=0x" << crash.program_counter << " in_oem=" << std::dec << pc_in_oem
           << std::hex;
    if (pc_in_oem) report << " oem_offset=0x" << pc_offset;
    report << "\n";
    report << "sp=0x" << crash.stack_pointer << " pstate=0x"
           << crash.processor_state << "\n";
    for (std::size_t index = 0; index < 31; ++index) {
        report << "x" << std::dec << index << std::hex << "=0x"
               << crash.registers[index] << "\n";
    }
    report << "lr=0x" << lr << " in_oem=" << std::dec << lr_in_oem << std::hex;
    if (lr_in_oem) report << " oem_offset=0x" << lr_offset;
    report << "\n";
}

bool IsReply(const std::array<std::uint8_t, sizeof(protocol::CrashFrame)>& packet,
             std::size_t packet_size, std::uint64_t attempt_id,
             protocol::ReplyFrame* reply) {
    if (packet_size != sizeof(*reply)) return false;
    memcpy(reply, packet.data(), sizeof(*reply));
    return ValidateHeader(reply->header, packet_size, attempt_id);
}

bool IsCrash(const std::array<std::uint8_t, sizeof(protocol::CrashFrame)>& packet,
             std::size_t packet_size, std::uint64_t attempt_id,
             protocol::CrashFrame* crash) {
    if (packet_size != sizeof(*crash)) return false;
    memcpy(crash, packet.data(), sizeof(*crash));
    return ValidateHeader(crash->header, packet_size, attempt_id) &&
           crash->header.type == static_cast<std::uint16_t>(protocol::FrameType::kCrashed);
}

}  // namespace

IsolatedVerifyResult VerifyCredentialIsolated(const std::string& credential,
                                               int expected_password_type) {
    if (credential.empty() || credential.size() > protocol::kMaxCredentialBytes ||
        expected_password_type < 1 || expected_password_type > 4) {
        LOGERR("[H40 V49 HELPER] refusing credential length=%zu passwordType=%d\n",
               credential.size(), expected_password_type);
        return IsolatedVerifyResult::kFatalFailure;
    }

    unlink("/tmp/h40-credential-helper.maps");
    unlink("/tmp/h40-credential-helper-crash.txt");

    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) {
        LOGERR("[H40 V49 HELPER] socketpair failed: %s\n", strerror(errno));
        return IsolatedVerifyResult::kFatalFailure;
    }
    ScopedFd parent_socket(sockets[0]);
    ScopedFd original_child_socket(sockets[1]);

    const int child_socket = fcntl(original_child_socket.get(), F_DUPFD_CLOEXEC, 64);
    if (child_socket < 0) {
        LOGERR("[H40 V49 HELPER] child fd duplication failed: %s\n", strerror(errno));
        return IsolatedVerifyResult::kFatalFailure;
    }
    ScopedFd spawned_socket(child_socket);

    posix_spawn_file_actions_t actions;
    int spawn_error = posix_spawn_file_actions_init(&actions);
    if (spawn_error != 0) {
        LOGERR("[H40 V49 HELPER] spawn action initialization failed: %s\n",
               strerror(spawn_error));
        return IsolatedVerifyResult::kFatalFailure;
    }
    spawn_error = posix_spawn_file_actions_adddup2(
            &actions, spawned_socket.get(), protocol::kProtocolFd);
    if (spawn_error == 0) {
        spawn_error = posix_spawn_file_actions_addclose(&actions, spawned_socket.get());
    }
    if (spawn_error != 0) {
        posix_spawn_file_actions_destroy(&actions);
        LOGERR("[H40 V49 HELPER] spawn action setup failed: %s\n", strerror(spawn_error));
        return IsolatedVerifyResult::kFatalFailure;
    }

    posix_spawnattr_t attributes;
    spawn_error = posix_spawnattr_init(&attributes);
    if (spawn_error != 0) {
        posix_spawn_file_actions_destroy(&actions);
        LOGERR("[H40 V49 HELPER] spawn attribute initialization failed: %s\n",
               strerror(spawn_error));
        return IsolatedVerifyResult::kFatalFailure;
    }
    sigset_t empty_signal_mask;
    sigemptyset(&empty_signal_mask);
    spawn_error = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSIGMASK);
    if (spawn_error == 0) {
        spawn_error = posix_spawnattr_setsigmask(&attributes, &empty_signal_mask);
    }
    if (spawn_error != 0) {
        posix_spawnattr_destroy(&attributes);
        posix_spawn_file_actions_destroy(&actions);
        LOGERR("[H40 V49 HELPER] spawn signal-mask setup failed: %s\n",
               strerror(spawn_error));
        return IsolatedVerifyResult::kFatalFailure;
    }

    char helper_path[] = "/system/bin/oplus_h40_credential_helper";
    char* argv[] = {helper_path, nullptr};
    char android_root[] = "ANDROID_ROOT=/system";
    char android_data[] = "ANDROID_DATA=/data";
    char path[] = "PATH=/system/bin";
    char* environment[] = {android_root, android_data, path, nullptr};
    pid_t pid = -1;
    spawn_error = posix_spawn(&pid, protocol::kHelperPath, &actions, &attributes, argv,
                               environment);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    if (spawn_error != 0) {
        LOGERR("[H40 V49 HELPER] posix_spawn failed: %s\n", strerror(spawn_error));
        return IsolatedVerifyResult::kFatalFailure;
    }
    close(spawned_socket.release());
    close(original_child_socket.release());

    const std::uint64_t attempt_id = MakeAttemptId();
    protocol::HelloFrame hello = {};
    hello.header = protocol::MakeHeader(protocol::FrameType::kHello, sizeof(hello), attempt_id);
    hello.user_id = 0;
    hello.expected_password_type = expected_password_type;
    if (!SendPacket(parent_socket.get(), &hello, sizeof(hello))) {
        LOGERR("[H40 V49 HELPER] failed to send hello attempt=%llu: %s\n",
               static_cast<unsigned long long>(attempt_id), strerror(errno));
        KillAndReap(pid);
        return IsolatedVerifyResult::kFatalFailure;
    }

    std::array<std::uint8_t, sizeof(protocol::CrashFrame)> packet = {};
    std::size_t packet_size = 0;
    ReceiveStatus receive = ReceivePacket(
            parent_socket.get(), MonotonicMilliseconds() + kSetupTimeoutMs,
            &packet, &packet_size);
    protocol::ReplyFrame reply = {};
    protocol::CrashFrame setup_crash = {};
    if (receive == ReceiveStatus::kPacket &&
        IsCrash(packet, packet_size, attempt_id, &setup_crash)) {
        SaveCrashReport(setup_crash, pid);
        int status = 0;
        if (!WaitForChild(pid, kExitTimeoutMs, &status)) KillAndReap(pid);
        return IsolatedVerifyResult::kFatalFailure;
    }
    if (receive == ReceiveStatus::kPacket &&
        IsReply(packet, packet_size, attempt_id, &reply) &&
        reply.header.type ==
                static_cast<std::uint16_t>(protocol::FrameType::kPreflightFailed)) {
        LOGERR("[H40 V49 HELPER] preflight failed attempt=%llu reason=%d stage=%u\n",
               static_cast<unsigned long long>(attempt_id), reply.result, reply.stage);
        int status = 0;
        if (!WaitForChild(pid, kExitTimeoutMs, &status)) KillAndReap(pid);
        return IsolatedVerifyResult::kFatalFailure;
    }
    if (receive != ReceiveStatus::kPacket ||
        !IsReply(packet, packet_size, attempt_id, &reply) ||
        reply.header.type != static_cast<std::uint16_t>(protocol::FrameType::kReady) ||
        reply.result != expected_password_type ||
        reply.stage != static_cast<std::uint32_t>(protocol::Stage::kDePrepared) ||
        reply.program_counter != 0 || reply.link_register != 0 ||
        reply.stack_pointer != 0 || reply.fault_address != 0 ||
        reply.oem_load_base == 0) {
        LOGERR("[H40 V49 HELPER] invalid/missing READY attempt=%llu status=%d\n",
               static_cast<unsigned long long>(attempt_id), static_cast<int>(receive));
        KillAndReap(pid);
        return IsolatedVerifyResult::kFatalFailure;
    }
    const std::uint64_t oem_load_base = reply.oem_load_base;
    if (!SaveHelperMaps(pid, attempt_id)) {
        KillAndReap(pid);
        return IsolatedVerifyResult::kFatalFailure;
    }

    std::vector<std::uint8_t> credential_packet(sizeof(protocol::CredentialFrame) +
                                                credential.size());
    protocol::CredentialFrame credential_header = {};
    credential_header.header = protocol::MakeHeader(
            protocol::FrameType::kCredential,
            static_cast<std::uint32_t>(credential_packet.size()), attempt_id);
    credential_header.user_id = 0;
    credential_header.credential_size =
            static_cast<std::uint32_t>(credential.size());
    memcpy(credential_packet.data(), &credential_header, sizeof(credential_header));
    memcpy(credential_packet.data() + sizeof(credential_header), credential.data(),
           credential.size());
    const bool credential_sent = SendPacket(parent_socket.get(), credential_packet.data(),
                                             credential_packet.size());
    explicit_bzero(credential_packet.data(), credential_packet.size());
    if (!credential_sent) {
        LOGERR("[H40 V49 HELPER] failed to send credential attempt=%llu: %s\n",
               static_cast<unsigned long long>(attempt_id), strerror(errno));
        KillAndReap(pid);
        return IsolatedVerifyResult::kFatalFailure;
    }

    bool verify_started = false;
    bool have_terminal_reply = false;
    protocol::FrameType terminal_type = protocol::FrameType::kPreflightFailed;
    std::int32_t terminal_result = 0;
    std::uint32_t terminal_stage = 0;
    const std::uint64_t verify_deadline = MonotonicMilliseconds() + kVerifyTimeoutMs;
    while (!have_terminal_reply) {
        packet.fill(0);
        packet_size = 0;
        receive = ReceivePacket(parent_socket.get(), verify_deadline, &packet, &packet_size);
        if (receive == ReceiveStatus::kTimeout) {
            LOGERR("[H40 V49 HELPER] timeout attempt=%llu verifyStarted=%d\n",
                   static_cast<unsigned long long>(attempt_id), verify_started);
            KillAndReap(pid);
            return IsolatedVerifyResult::kFatalFailure;
        }
        if (receive != ReceiveStatus::kPacket) {
            int status = 0;
            const bool reaped = WaitForChild(pid, kExitTimeoutMs, &status);
            LOGERR("[H40 V49 HELPER] channel closed attempt=%llu verifyStarted=%d "
                   "reaped=%d status=%d\n",
                   static_cast<unsigned long long>(attempt_id), verify_started, reaped, status);
            if (!reaped) KillAndReap(pid);
            return IsolatedVerifyResult::kFatalFailure;
        }

        protocol::CrashFrame crash = {};
        if (IsCrash(packet, packet_size, attempt_id, &crash)) {
            SaveCrashReport(crash, pid);
            int status = 0;
            if (!WaitForChild(pid, kExitTimeoutMs, &status)) KillAndReap(pid);
            return IsolatedVerifyResult::kFatalFailure;
        }
        if (!IsReply(packet, packet_size, attempt_id, &reply)) {
            LOGERR("[H40 V49 HELPER] malformed reply attempt=%llu size=%zu\n",
                   static_cast<unsigned long long>(attempt_id), packet_size);
            KillAndReap(pid);
            return IsolatedVerifyResult::kFatalFailure;
        }

        const bool clean_diagnostics = reply.program_counter == 0 &&
                                       reply.link_register == 0 &&
                                       reply.stack_pointer == 0 &&
                                       reply.fault_address == 0 &&
                                       reply.oem_load_base == oem_load_base;
        if (!clean_diagnostics) {
            LOGERR("[H40 V49 HELPER] invalid reply diagnostics attempt=%llu type=%u\n",
                   static_cast<unsigned long long>(attempt_id), reply.header.type);
            KillAndReap(pid);
            return IsolatedVerifyResult::kFatalFailure;
        }

        const protocol::FrameType type =
                static_cast<protocol::FrameType>(reply.header.type);
        if (type == protocol::FrameType::kVerifyStarted && !verify_started &&
            reply.result == 0 &&
            reply.stage == static_cast<std::uint32_t>(protocol::Stage::kVerifyStarted)) {
            verify_started = true;
            LOGINFO("[H40 V49 HELPER] OEM verify started attempt=%llu base=0x%llx\n",
                    static_cast<unsigned long long>(attempt_id),
                    static_cast<unsigned long long>(reply.oem_load_base));
            continue;
        }
        const bool valid_accepted = type == protocol::FrameType::kAccepted &&
                                    verify_started && reply.result == 0 &&
                                    reply.stage == static_cast<std::uint32_t>(
                                                           protocol::Stage::kCeInitialized);
        const bool valid_rejected = type == protocol::FrameType::kRejected &&
                                    verify_started && reply.result != 0 &&
                                    reply.stage == static_cast<std::uint32_t>(
                                                           protocol::Stage::kVerifyReturned);
        const bool valid_preflight_failure =
                type == protocol::FrameType::kPreflightFailed && reply.result > 0 &&
                reply.result <= static_cast<std::int32_t>(protocol::Failure::kIoFailed) &&
                reply.stage >= static_cast<std::uint32_t>(protocol::Stage::kStarting) &&
                reply.stage <= static_cast<std::uint32_t>(protocol::Stage::kCeInitialized);
        if (valid_accepted || valid_rejected || valid_preflight_failure) {
            terminal_type = type;
            terminal_result = reply.result;
            terminal_stage = reply.stage;
            have_terminal_reply = true;
            continue;
        }
        LOGERR("[H40 V49 HELPER] unexpected reply type=%u attempt=%llu\n",
               reply.header.type, static_cast<unsigned long long>(attempt_id));
        KillAndReap(pid);
        return IsolatedVerifyResult::kFatalFailure;
    }

    int child_status = 0;
    if (!WaitForChild(pid, kExitTimeoutMs, &child_status)) {
        LOGERR("[H40 V49 HELPER] helper failed to exit attempt=%llu\n",
               static_cast<unsigned long long>(attempt_id));
        KillAndReap(pid);
        return IsolatedVerifyResult::kFatalFailure;
    }
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        LOGERR("[H40 V49 HELPER] abnormal exit attempt=%llu status=%d terminal=%u\n",
               static_cast<unsigned long long>(attempt_id), child_status,
               static_cast<unsigned int>(terminal_type));
        return IsolatedVerifyResult::kFatalFailure;
    }
    if (terminal_type == protocol::FrameType::kAccepted && verify_started) {
        LOGINFO("[H40 V49 HELPER] credential accepted attempt=%llu\n",
                static_cast<unsigned long long>(attempt_id));
        return IsolatedVerifyResult::kAccepted;
    }
    if (terminal_type == protocol::FrameType::kRejected && verify_started) {
        LOGINFO("[H40 V49 HELPER] credential rejected normally attempt=%llu\n",
                static_cast<unsigned long long>(attempt_id));
        return IsolatedVerifyResult::kRejected;
    }
    LOGERR("[H40 V49 HELPER] fatal terminal state=%u result=%d stage=%u "
           "verifyStarted=%d attempt=%llu\n",
           static_cast<unsigned int>(terminal_type), terminal_result, terminal_stage,
           verify_started,
           static_cast<unsigned long long>(attempt_id));
    return IsolatedVerifyResult::kFatalFailure;
}

}  // namespace oplus_h40
}  // namespace twrp
