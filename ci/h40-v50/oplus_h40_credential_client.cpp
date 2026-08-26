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

#include <algorithm>
#include <array>
#include <climits>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "twcommon.h"

namespace twrp {
namespace oplus_h40 {
namespace {

namespace protocol = credential_protocol;

constexpr int kSetupTimeoutMs = 30000;
constexpr int kVerifyTimeoutMs = 60000;
constexpr int kExitTimeoutMs = 5000;

void SecureWipe(void* data, std::size_t size) {
    volatile std::uint8_t* bytes = static_cast<volatile std::uint8_t*>(data);
    while (size != 0) {
        *bytes++ = 0;
        --size;
    }
}

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
        LOGERR("[H40 V50 HELPER] failed to kill helper pid=%d: %s\n", pid,
               strerror(errno));
    }
    int status = 0;
    if (!WaitForChild(pid, kExitTimeoutMs, &status)) {
        LOGERR("[H40 V50 HELPER] helper pid=%d did not reap after SIGKILL; "
               "continuing in fatal adapter state\n",
               pid);
    }
}

struct OemMapping {
    std::uint64_t load_base = 0;
    struct ExecutableInterval {
        std::uint64_t start = 0;
        std::uint64_t end = 0;
    };
    std::vector<ExecutableInterval> executable_intervals;
};

bool CaptureHelperMaps(pid_t pid, std::uint64_t attempt_id, OemMapping* oem_mapping) {
    const std::string source = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream input(source);
    if (!input.is_open() || oem_mapping == nullptr) {
        LOGERR("[H40 V50 HELPER] unable to inspect helper maps for attempt=%llu\n",
               static_cast<unsigned long long>(attempt_id));
        return false;
    }
    bool saw_oem = false;
    bool saw_stock_libcxx = false;
    bool saw_stock_libcrypto = false;
    bool saw_helper = false;
    bool saw_private_runtime = false;
    std::uint64_t oem_start = std::numeric_limits<std::uint64_t>::max();
    std::vector<OemMapping::ExecutableInterval> executable_intervals;
    std::string line;
    while (std::getline(input, line)) {
        const bool is_oem =
                line.find("/system/lib64/libdecrypt_recovery.so") != std::string::npos;
        saw_oem = saw_oem || is_oem;
        saw_stock_libcxx = saw_stock_libcxx ||
                          line.find("/system/lib64/libc++.so") != std::string::npos;
        saw_stock_libcrypto = saw_stock_libcrypto ||
                              line.find("/system/lib64/libcrypto.so") !=
                                      std::string::npos;
        saw_helper = saw_helper ||
                     line.find("/system/bin/oplus_h40_credential_helper") !=
                             std::string::npos;
        saw_private_runtime = saw_private_runtime ||
                              line.find("/system/tw/") != std::string::npos;
        if (is_oem) {
            unsigned long long start = 0;
            unsigned long long end = 0;
            char permissions[5] = {};
            if (std::sscanf(line.c_str(), "%llx-%llx %4s", &start, &end,
                            permissions) != 3 || start >= end) {
                LOGERR("[H40 V50 HELPER] malformed OEM map attempt=%llu\n",
                       static_cast<unsigned long long>(attempt_id));
                return false;
            }
            oem_start = std::min(oem_start, static_cast<std::uint64_t>(start));
            if (strchr(permissions, 'x') != nullptr) {
                executable_intervals.push_back(
                        {static_cast<std::uint64_t>(start),
                         static_cast<std::uint64_t>(end)});
            }
        }
    }
    if (!saw_oem || executable_intervals.empty() || !saw_stock_libcxx ||
        !saw_stock_libcrypto || !saw_helper || saw_private_runtime ||
        oem_start == std::numeric_limits<std::uint64_t>::max()) {
        LOGERR("[H40 V50 HELPER] stock namespace proof failed attempt=%llu "
               "helper=%d oem=%d executable=%d stockLibcxx=%d "
               "stockLibcrypto=%d privateRuntime=%d\n",
               static_cast<unsigned long long>(attempt_id), saw_helper, saw_oem,
               !executable_intervals.empty(), saw_stock_libcxx, saw_stock_libcrypto,
               saw_private_runtime);
        return false;
    }

    std::sort(executable_intervals.begin(), executable_intervals.end(),
              [](const OemMapping::ExecutableInterval& left,
                 const OemMapping::ExecutableInterval& right) {
                  return left.start < right.start;
              });
    std::uint64_t previous_end = 0;
    for (const OemMapping::ExecutableInterval& interval : executable_intervals) {
        if (interval.start < oem_start || interval.end <= interval.start ||
            (previous_end != 0 && interval.start < previous_end)) {
            LOGERR("[H40 V50 HELPER] invalid OEM executable-map layout attempt=%llu\n",
                   static_cast<unsigned long long>(attempt_id));
            return false;
        }
        previous_end = interval.end;
    }
    oem_mapping->load_base = oem_start;
    oem_mapping->executable_intervals = std::move(executable_intervals);
    LOGINFO("[H40 V50 HELPER] stock-runtime maps verified for attempt=%llu pid=%d\n",
            static_cast<unsigned long long>(attempt_id), pid);
    return true;
}

bool OffsetInOemExecutableMapping(std::uint64_t offset,
                                  const OemMapping& mapping) {
    if (mapping.load_base == 0 ||
        offset > std::numeric_limits<std::uint64_t>::max() - mapping.load_base) {
        return false;
    }
    const std::uint64_t address = mapping.load_base + offset;
    for (const OemMapping::ExecutableInterval& interval :
         mapping.executable_intervals) {
        if (address >= interval.start && address < interval.end) return true;
    }
    return false;
}

void SaveCrashReport(const protocol::CrashFrame& crash, pid_t pid,
                     const OemMapping& mapping) {
    const bool pc_claimed =
            (crash.address_flags & protocol::kCrashPcOemExecutable) != 0;
    const bool pc_in_oem =
            pc_claimed && OffsetInOemExecutableMapping(
                                  crash.program_counter_offset, mapping);
    const std::uint64_t pc_offset = pc_in_oem ? crash.program_counter_offset : 0;
    const bool lr_claimed =
            (crash.address_flags & protocol::kCrashLrOemExecutable) != 0;
    const bool lr_in_oem =
            lr_claimed && OffsetInOemExecutableMapping(
                                  crash.link_register_offset, mapping);
    const std::uint64_t lr_offset = lr_in_oem ? crash.link_register_offset : 0;

    LOGERR("[H40 V50 CRASH] helper pid=%d tid=%u signal=%d code=%d stage=%u "
           "pcInOem=%d pcOffset=0x%llx lrInOem=%d lrOffset=0x%llx\n",
           pid, crash.crashing_tid, crash.signal_number, crash.signal_code, crash.stage,
           pc_in_oem, static_cast<unsigned long long>(pc_offset), lr_in_oem,
           static_cast<unsigned long long>(lr_offset));

    std::ofstream report("/tmp/h40-credential-helper-crash.txt", std::ios::trunc);
    if (!report.is_open()) return;
    report << "attempt=" << std::dec << crash.header.attempt_id << " pid=" << pid
           << " tid=" << crash.crashing_tid
           << " signal=" << crash.signal_number << " code=" << crash.signal_code
           << " stage=" << crash.stage << "\n";
    report << "pc_in_oem=" << pc_in_oem;
    if (pc_in_oem) report << " oem_offset=0x" << std::hex << pc_offset << std::dec;
    report << "\n";
    report << "lr_in_oem=" << lr_in_oem;
    if (lr_in_oem) report << " oem_offset=0x" << std::hex << lr_offset << std::dec;
    report << "\n";
}

bool IsReply(const std::array<std::uint8_t, sizeof(protocol::CrashFrame)>& packet,
             std::size_t packet_size, std::uint64_t attempt_id,
             protocol::ReplyFrame* reply) {
    if (packet_size != sizeof(*reply)) return false;
    memcpy(reply, packet.data(), sizeof(*reply));
    return ValidateHeader(reply->header, packet_size, attempt_id) &&
           reply->reserved == 0 &&
           (reply->flags & ~protocol::kKnownReplyFlags) == 0;
}

bool IsCrash(const std::array<std::uint8_t, sizeof(protocol::CrashFrame)>& packet,
             std::size_t packet_size, std::uint64_t attempt_id,
             protocol::CrashFrame* crash) {
    if (packet_size != sizeof(*crash)) return false;
    memcpy(crash, packet.data(), sizeof(*crash));
    return ValidateHeader(crash->header, packet_size, attempt_id) &&
           crash->header.type ==
                   static_cast<std::uint16_t>(protocol::FrameType::kCrashed) &&
           crash->reserved == 0 &&
           (crash->address_flags & ~protocol::kKnownCrashAddressFlags) == 0 &&
           (((crash->address_flags & protocol::kCrashPcOemExecutable) != 0) ||
            crash->program_counter_offset == 0) &&
           (((crash->address_flags & protocol::kCrashLrOemExecutable) != 0) ||
            crash->link_register_offset == 0);
}

}  // namespace

IsolatedVerifyResult VerifyCredentialIsolated(const std::string& credential,
                                               int expected_password_type) {
    if (credential.empty() || credential.size() > protocol::kMaxCredentialBytes ||
        expected_password_type < 1 || expected_password_type > 4) {
        LOGERR("[H40 V50 HELPER] refusing malformed credential parameters\n");
        return IsolatedVerifyResult::kFatalFailure;
    }

    unlink("/tmp/h40-credential-helper-crash.txt");

    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) {
        LOGERR("[H40 V50 HELPER] socketpair failed: %s\n", strerror(errno));
        return IsolatedVerifyResult::kFatalFailure;
    }
    ScopedFd parent_socket(sockets[0]);
    ScopedFd original_child_socket(sockets[1]);

    const int child_socket = fcntl(original_child_socket.get(), F_DUPFD_CLOEXEC, 64);
    if (child_socket < 0) {
        LOGERR("[H40 V50 HELPER] child fd duplication failed: %s\n", strerror(errno));
        return IsolatedVerifyResult::kFatalFailure;
    }
    ScopedFd spawned_socket(child_socket);

    posix_spawn_file_actions_t actions;
    int spawn_error = posix_spawn_file_actions_init(&actions);
    if (spawn_error != 0) {
        LOGERR("[H40 V50 HELPER] spawn action initialization failed: %s\n",
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
        LOGERR("[H40 V50 HELPER] spawn action setup failed: %s\n", strerror(spawn_error));
        return IsolatedVerifyResult::kFatalFailure;
    }

    posix_spawnattr_t attributes;
    spawn_error = posix_spawnattr_init(&attributes);
    if (spawn_error != 0) {
        posix_spawn_file_actions_destroy(&actions);
        LOGERR("[H40 V50 HELPER] spawn attribute initialization failed: %s\n",
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
        LOGERR("[H40 V50 HELPER] spawn signal-mask setup failed: %s\n",
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
        LOGERR("[H40 V50 HELPER] posix_spawn failed: %s\n", strerror(spawn_error));
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
        LOGERR("[H40 V50 HELPER] failed to send hello attempt=%llu: %s\n",
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
        SaveCrashReport(setup_crash, pid, OemMapping{});
        int status = 0;
        if (!WaitForChild(pid, kExitTimeoutMs, &status)) KillAndReap(pid);
        return IsolatedVerifyResult::kFatalFailure;
    }
    if (receive == ReceiveStatus::kPacket &&
        IsReply(packet, packet_size, attempt_id, &reply) &&
        reply.header.type ==
                static_cast<std::uint16_t>(protocol::FrameType::kPreflightFailed)) {
        LOGERR("[H40 V50 HELPER] preflight failed attempt=%llu reason=%d stage=%u\n",
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
        reply.flags != protocol::kReplyOemIdentityVerified) {
        LOGERR("[H40 V50 HELPER] invalid/missing READY attempt=%llu status=%d\n",
               static_cast<unsigned long long>(attempt_id), static_cast<int>(receive));
        KillAndReap(pid);
        return IsolatedVerifyResult::kFatalFailure;
    }
    OemMapping oem_mapping;
    if (!CaptureHelperMaps(pid, attempt_id, &oem_mapping)) {
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
    SecureWipe(credential_packet.data(), credential_packet.size());
    if (!credential_sent) {
        LOGERR("[H40 V50 HELPER] failed to send credential attempt=%llu: %s\n",
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
            LOGERR("[H40 V50 HELPER] timeout attempt=%llu verifyStarted=%d\n",
                   static_cast<unsigned long long>(attempt_id), verify_started);
            KillAndReap(pid);
            return IsolatedVerifyResult::kFatalFailure;
        }
        if (receive != ReceiveStatus::kPacket) {
            int status = 0;
            const bool reaped = WaitForChild(pid, kExitTimeoutMs, &status);
            LOGERR("[H40 V50 HELPER] channel closed attempt=%llu verifyStarted=%d "
                   "reaped=%d status=%d\n",
                   static_cast<unsigned long long>(attempt_id), verify_started, reaped, status);
            if (!reaped) KillAndReap(pid);
            return IsolatedVerifyResult::kFatalFailure;
        }

        protocol::CrashFrame crash = {};
        if (IsCrash(packet, packet_size, attempt_id, &crash)) {
            SaveCrashReport(crash, pid, oem_mapping);
            int status = 0;
            if (!WaitForChild(pid, kExitTimeoutMs, &status)) KillAndReap(pid);
            return IsolatedVerifyResult::kFatalFailure;
        }
        if (!IsReply(packet, packet_size, attempt_id, &reply)) {
            LOGERR("[H40 V50 HELPER] malformed reply attempt=%llu size=%zu\n",
                   static_cast<unsigned long long>(attempt_id), packet_size);
            KillAndReap(pid);
            return IsolatedVerifyResult::kFatalFailure;
        }

        const bool clean_diagnostics =
                reply.flags == protocol::kReplyOemIdentityVerified;
        if (!clean_diagnostics) {
            LOGERR("[H40 V50 HELPER] invalid reply diagnostics attempt=%llu type=%u\n",
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
            LOGINFO("[H40 V50 HELPER] OEM verify started attempt=%llu\n",
                    static_cast<unsigned long long>(attempt_id));
            continue;
        }
        const bool valid_accepted = type == protocol::FrameType::kAccepted &&
                                    verify_started && reply.result == 0 &&
                                    reply.stage == static_cast<std::uint32_t>(
                                                           protocol::Stage::kCredentialAccepted);
        const bool valid_rejected = type == protocol::FrameType::kRejected &&
                                    verify_started && reply.result == -1 &&
                                    reply.stage == static_cast<std::uint32_t>(
                                                           protocol::Stage::kVerifyReturned);
        const bool valid_preflight_failure =
                type == protocol::FrameType::kPreflightFailed && reply.result > 0 &&
                reply.result <=
                        static_cast<std::int32_t>(
                                protocol::Failure::kUnexpectedVerifyResult) &&
                reply.stage >= static_cast<std::uint32_t>(protocol::Stage::kStarting) &&
                reply.stage <=
                        static_cast<std::uint32_t>(protocol::Stage::kCredentialAccepted);
        if (valid_accepted || valid_rejected || valid_preflight_failure) {
            terminal_type = type;
            terminal_result = reply.result;
            terminal_stage = reply.stage;
            have_terminal_reply = true;
            continue;
        }
        LOGERR("[H40 V50 HELPER] unexpected reply type=%u attempt=%llu\n",
               reply.header.type, static_cast<unsigned long long>(attempt_id));
        KillAndReap(pid);
        return IsolatedVerifyResult::kFatalFailure;
    }

    int child_status = 0;
    if (!WaitForChild(pid, kExitTimeoutMs, &child_status)) {
        LOGERR("[H40 V50 HELPER] helper failed to exit attempt=%llu\n",
               static_cast<unsigned long long>(attempt_id));
        KillAndReap(pid);
        return IsolatedVerifyResult::kFatalFailure;
    }
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        LOGERR("[H40 V50 HELPER] abnormal exit attempt=%llu status=%d terminal=%u\n",
               static_cast<unsigned long long>(attempt_id), child_status,
               static_cast<unsigned int>(terminal_type));
        return IsolatedVerifyResult::kFatalFailure;
    }
    if (terminal_type == protocol::FrameType::kAccepted && verify_started) {
        LOGINFO("[H40 V50 HELPER] credential accepted attempt=%llu\n",
                static_cast<unsigned long long>(attempt_id));
        return IsolatedVerifyResult::kAccepted;
    }
    if (terminal_type == protocol::FrameType::kRejected && verify_started) {
        LOGINFO("[H40 V50 HELPER] OEM returned -1/non-acceptance attempt=%llu\n",
                static_cast<unsigned long long>(attempt_id));
        return IsolatedVerifyResult::kRejected;
    }
    LOGERR("[H40 V50 HELPER] fatal terminal state=%u result=%d stage=%u "
           "verifyStarted=%d attempt=%llu\n",
           static_cast<unsigned int>(terminal_type), terminal_result, terminal_stage,
           verify_started,
           static_cast<unsigned long long>(attempt_id));
    return IsolatedVerifyResult::kFatalFailure;
}

}  // namespace oplus_h40
}  // namespace twrp
