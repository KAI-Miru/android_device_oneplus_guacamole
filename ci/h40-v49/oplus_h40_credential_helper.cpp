#define LOG_TAG "H40Credential49"

#include "oplus_h40_credential_protocol.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <keyutils.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <string.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

namespace {

namespace protocol = twrp::oplus_h40::credential_protocol;

constexpr char kVerifySymbol[] =
        "_Z21OplusCredentialVerifyNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEi";
constexpr char kSetupDeCeSymbol[] = "_Z11setup_de_cei";
constexpr char kGetPasswordTypeSymbol[] = "_Z17get_password_typei";
constexpr char kInitUser0CeSymbol[] = "_Z21fscrypt_init_user0_cev";

using VerifyFn = int (*)(std::string, int);
using SetupDeCeFn = bool (*)(int);
using GetPasswordTypeFn = int (*)(int);
using InitUser0CeFn = bool (*)();

alignas(16) unsigned char g_signal_stack[64 * 1024];
alignas(4) std::uint32_t g_stage =
        static_cast<std::uint32_t>(protocol::Stage::kStarting);
alignas(8) std::uint64_t g_attempt_id = 0;
alignas(8) std::uint64_t g_oem_load_base = 0;
static_assert(__atomic_always_lock_free(sizeof(std::uint32_t), nullptr),
              "signal packet requires lock-free 32-bit atomics");
static_assert(__atomic_always_lock_free(sizeof(std::uint64_t), nullptr),
              "signal packet requires lock-free 64-bit atomics");

std::uint32_t LoadStage() {
    return __atomic_load_n(&g_stage, __ATOMIC_RELAXED);
}

void StoreStage(protocol::Stage stage) {
    __atomic_store_n(&g_stage, static_cast<std::uint32_t>(stage), __ATOMIC_RELAXED);
}

std::uint64_t LoadAttemptId() {
    return __atomic_load_n(&g_attempt_id, __ATOMIC_RELAXED);
}

void StoreAttemptId(std::uint64_t attempt_id) {
    __atomic_store_n(&g_attempt_id, attempt_id, __ATOMIC_RELAXED);
}

std::uint64_t LoadOemBase() {
    return __atomic_load_n(&g_oem_load_base, __ATOMIC_RELAXED);
}

void StoreOemBase(std::uint64_t base) {
    __atomic_store_n(&g_oem_load_base, base, __ATOMIC_RELAXED);
}

bool SendReply(protocol::FrameType type, std::int32_t result, protocol::Stage stage) {
    protocol::ReplyFrame reply = {};
    reply.header = protocol::MakeHeader(type, sizeof(reply), LoadAttemptId());
    reply.result = result;
    reply.stage = static_cast<std::uint32_t>(stage);
    reply.oem_load_base = LoadOemBase();
    return write(protocol::kProtocolFd, &reply, sizeof(reply)) ==
           static_cast<ssize_t>(sizeof(reply));
}

[[noreturn]] void Finish(protocol::FrameType type, std::int32_t result,
                         protocol::Stage stage) {
    SendReply(type, result, stage);
    _exit(0);
}

void CrashHandler(int signal_number, siginfo_t* info, void* raw_context) {
    const int saved_errno = errno;
    protocol::CrashFrame crash = {};
    crash.header.magic = protocol::kMagic;
    crash.header.version = protocol::kVersion;
    crash.header.type = static_cast<std::uint16_t>(protocol::FrameType::kCrashed);
    crash.header.frame_size = sizeof(crash);
    crash.header.attempt_id = LoadAttemptId();
    crash.signal_number = signal_number;
    crash.stage = LoadStage();
    crash.signal_code = info == nullptr ? 0 : info->si_code;
    crash.crashing_tid = static_cast<std::uint32_t>(syscall(__NR_gettid));
    crash.fault_address = info == nullptr
                                  ? 0
                                  : reinterpret_cast<std::uintptr_t>(info->si_addr);
    crash.oem_load_base = LoadOemBase();
#if defined(__aarch64__)
    if (raw_context != nullptr) {
        const ucontext_t* context = static_cast<const ucontext_t*>(raw_context);
        for (std::size_t index = 0; index < 31; ++index) {
            crash.registers[index] = context->uc_mcontext.regs[index];
        }
        crash.stack_pointer = context->uc_mcontext.sp;
        crash.program_counter = context->uc_mcontext.pc;
        crash.processor_state = context->uc_mcontext.pstate;
    }
#endif
    errno = saved_errno;
    const ssize_t ignored = write(protocol::kProtocolFd, &crash, sizeof(crash));
    (void)ignored;
    _exit(128 + signal_number);
}

bool InstallCrashHandler() {
    stack_t stack = {};
    stack.ss_sp = g_signal_stack;
    stack.ss_size = sizeof(g_signal_stack);
    if (sigaltstack(&stack, nullptr) != 0) return false;

    struct sigaction action = {};
    action.sa_sigaction = CrashHandler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
    // Block every maskable signal while the fatal handler composes its single
    // fixed packet; a second fault must not re-enter the alternate stack.
    sigfillset(&action.sa_mask);
    constexpr int signals[] = {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE};
    for (int signal_number : signals) {
        if (sigaction(signal_number, &action, nullptr) != 0) return false;
    }
    return true;
}

bool ReadHello(protocol::HelloFrame* hello) {
    std::array<std::uint8_t, sizeof(protocol::CrashFrame)> packet = {};
    const ssize_t received = recv(protocol::kProtocolFd, packet.data(), packet.size(), MSG_TRUNC);
    if (received != static_cast<ssize_t>(sizeof(*hello))) return false;
    memcpy(hello, packet.data(), sizeof(*hello));
    if (hello->header.magic != protocol::kMagic ||
        hello->header.version != protocol::kVersion ||
        hello->header.type != static_cast<std::uint16_t>(protocol::FrameType::kHello) ||
        hello->header.frame_size != sizeof(*hello) || hello->header.reserved != 0 ||
        hello->header.attempt_id == 0 || hello->user_id != 0 ||
        hello->expected_password_type < 1 || hello->expected_password_type > 4) {
        return false;
    }
    return true;
}

bool CheckDeLayout() {
    struct stat status = {};
    if (stat("/data/system_de/0/spblob", &status) != 0 || !S_ISDIR(status.st_mode)) {
        return false;
    }
    if (stat("/data/system/users/0.xml", &status) != 0 || !S_ISREG(status.st_mode)) {
        return false;
    }
    return access("/data/system_de/0/spblob", R_OK | X_OK) == 0 &&
           access("/data/system/users/0.xml", R_OK) == 0;
}

template <typename T>
T Resolve(void* handle, const char* symbol, void** raw_symbol = nullptr) {
    dlerror();
    void* raw = dlsym(handle, symbol);
    const char* error = dlerror();
    if (error != nullptr || raw == nullptr) return nullptr;
    if (raw_symbol != nullptr) *raw_symbol = raw;
    return reinterpret_cast<T>(raw);
}

bool ReadCredential(std::uint64_t attempt_id, std::string* credential) {
    std::array<std::uint8_t,
               sizeof(protocol::CredentialFrame) + protocol::kMaxCredentialBytes>
            packet = {};
    const ssize_t received = recv(protocol::kProtocolFd, packet.data(), packet.size(), MSG_TRUNC);
    if (received < static_cast<ssize_t>(sizeof(protocol::CredentialFrame)) ||
        received > static_cast<ssize_t>(packet.size())) {
        return false;
    }
    protocol::CredentialFrame frame = {};
    memcpy(&frame, packet.data(), sizeof(frame));
    const std::size_t packet_size = static_cast<std::size_t>(received);
    if (frame.header.magic != protocol::kMagic ||
        frame.header.version != protocol::kVersion ||
        frame.header.type != static_cast<std::uint16_t>(protocol::FrameType::kCredential) ||
        frame.header.frame_size != packet_size || frame.header.reserved != 0 ||
        frame.header.attempt_id != attempt_id || frame.user_id != 0 ||
        frame.credential_size == 0 ||
        frame.credential_size > protocol::kMaxCredentialBytes ||
        packet_size != sizeof(frame) + frame.credential_size) {
        explicit_bzero(packet.data(), packet.size());
        return false;
    }

    const char* bytes = reinterpret_cast<const char*>(packet.data() + sizeof(frame));
    if (memchr(bytes, '\0', frame.credential_size) != nullptr) {
        explicit_bzero(packet.data(), packet.size());
        return false;
    }
    credential->assign(bytes, frame.credential_size);
    explicit_bzero(packet.data(), packet.size());
    return true;
}

}  // namespace

int main() {
    protocol::HelloFrame hello = {};
    if (!ReadHello(&hello)) return 2;
    StoreAttemptId(hello.header.attempt_id);
    if (!InstallCrashHandler()) {
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kIoFailed),
               protocol::Stage::kStarting);
    }

    errno = 0;
    const key_serial_t keyring =
            keyctl_search(KEY_SPEC_SESSION_KEYRING, "keyring", "fscrypt", 0);
    if (keyring < 0) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                            "session fscrypt keyring unavailable: %s", strerror(errno));
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kSessionKeyringUnavailable),
               protocol::Stage::kStarting);
    }

    void* handle = dlopen(protocol::kOemLibraryPath, RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "OEM dlopen failed: %s", dlerror());
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kLibraryLoadFailed),
               protocol::Stage::kStarting);
    }

    void* raw_verify = nullptr;
    const VerifyFn verify = Resolve<VerifyFn>(handle, kVerifySymbol, &raw_verify);
    const SetupDeCeFn setup_de_ce = Resolve<SetupDeCeFn>(handle, kSetupDeCeSymbol);
    const GetPasswordTypeFn get_password_type =
            Resolve<GetPasswordTypeFn>(handle, kGetPasswordTypeSymbol);
    const InitUser0CeFn init_user0_ce = Resolve<InitUser0CeFn>(handle, kInitUser0CeSymbol);
    if (verify == nullptr || setup_de_ce == nullptr || get_password_type == nullptr ||
        init_user0_ce == nullptr) {
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kSymbolMissing),
               protocol::Stage::kStarting);
    }

    Dl_info library_info = {};
    if (dladdr(raw_verify, &library_info) != 0 && library_info.dli_fbase != nullptr) {
        StoreOemBase(reinterpret_cast<std::uintptr_t>(library_info.dli_fbase));
    }
    StoreStage(protocol::Stage::kLibraryLoaded);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                        "stock OEM library loaded base=0x%llx keyring=%d",
                        static_cast<unsigned long long>(LoadOemBase()),
                        static_cast<int>(keyring));

    if (!setup_de_ce(0)) {
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kSetupDeCeFailed),
               protocol::Stage::kLibraryLoaded);
    }
    StoreStage(protocol::Stage::kDePrepared);
    const int password_type = get_password_type(0);
    if (password_type < 1 || password_type > 4 ||
        password_type != hello.expected_password_type) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                            "password type mismatch: expected=%d actual=%d",
                            hello.expected_password_type, password_type);
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kPasswordTypeInvalid),
               protocol::Stage::kDePrepared);
    }
    if (!CheckDeLayout()) {
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kDeLayoutInvalid),
               protocol::Stage::kDePrepared);
    }
    if (!SendReply(protocol::FrameType::kReady, password_type,
                   protocol::Stage::kDePrepared)) {
        _exit(3);
    }

    std::string credential;
    if (!ReadCredential(LoadAttemptId(), &credential)) {
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kInvalidFrame),
               protocol::Stage::kDePrepared);
    }
    if (!SendReply(protocol::FrameType::kVerifyStarted, 0,
                   protocol::Stage::kVerifyStarted)) {
        explicit_bzero(&credential[0], credential.size());
        _exit(3);
    }
    StoreStage(protocol::Stage::kVerifyStarted);

    const int verify_result = verify(std::move(credential), 0);
    StoreStage(protocol::Stage::kVerifyReturned);
    if (verify_result != 0) {
        Finish(protocol::FrameType::kRejected, verify_result,
               protocol::Stage::kVerifyReturned);
    }

    if (!init_user0_ce()) {
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kCeInitializationFailed),
               protocol::Stage::kVerifyReturned);
    }
    StoreStage(protocol::Stage::kCeInitialized);
    Finish(protocol::FrameType::kAccepted, 0, protocol::Stage::kCeInitialized);
}
