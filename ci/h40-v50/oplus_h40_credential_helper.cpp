#define LOG_TAG "H40Credential50"

#include "oplus_h40_credential_protocol.hpp"

#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <keyutils.h>
#include <link.h>
#include <openssl/sha.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <string.h>

#include <array>
#include <climits>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>

namespace {

namespace protocol = twrp::oplus_h40::credential_protocol;

constexpr char kVerifySymbol[] =
        "_Z21OplusCredentialVerifyNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEi";
constexpr char kSetupDeCeSymbol[] = "_Z11setup_de_cei";
constexpr char kGetPasswordTypeSymbol[] = "_Z17get_password_typei";

using VerifyFn = int (*)(std::string, int);
using SetupDeCeFn = bool (*)(int);
using GetPasswordTypeFn = int (*)(int);

constexpr off_t kExpectedOemFileSize = 1479432;
constexpr std::array<std::uint8_t, SHA256_DIGEST_LENGTH> kExpectedOemSha256 = {
        0xd7, 0xff, 0x48, 0x88, 0xd8, 0x80, 0x40, 0x59,
        0x6b, 0x7c, 0xa6, 0xc1, 0x1e, 0xe9, 0x89, 0x89,
        0x3b, 0x6c, 0xef, 0x91, 0xba, 0x56, 0x51, 0x20,
        0x29, 0x61, 0x71, 0x6f, 0x8e, 0x7d, 0xe2, 0xa2,
};
constexpr std::uintptr_t kVerifySymbolOffset = 0x826ec;
constexpr std::uintptr_t kSetupDeCeSymbolOffset = 0x822f0;
constexpr std::uintptr_t kGetPasswordTypeSymbolOffset = 0x80ab8;
constexpr std::uintptr_t kCredentialLogCallOffset = 0x82adc;
constexpr std::uintptr_t kLegacyCeInitCallOffset = 0x82bb0;
constexpr std::uint32_t kCredentialLogCallInstruction = 0x9403648d;
constexpr std::uint32_t kLegacyCeInitCallInstruction = 0x940365d8;
constexpr std::uint32_t kAarch64Nop = 0xd503201f;
constexpr std::uint32_t kAarch64MovW0One = 0x52800020;

struct OpcodeExpectation {
    std::uintptr_t offset;
    std::uint32_t original;
};

constexpr OpcodeExpectation kVerifierOpcodeContext[] = {
        {0x82ad0, 0x2a1303e1},  // mov w1, w19
        {0x82ad4, 0xaa1f03e2},  // mov x2, xzr
        {0x82ad8, 0xaa1403e5},  // mov x5, x20
        {kCredentialLogCallOffset, kCredentialLogCallInstruction},
        {0x82ae0, 0xf9403fe0},  // ldr x0, [sp, #0x78]
        {0x82bac, 0x34000113},  // cbz w19, rejected return
        {kLegacyCeInitCallOffset, kLegacyCeInitCallInstruction},
        {0x82bb4, 0x37000080},  // tbnz w0, #0, accepted return
        {0x82bc4, 0x2a1f03e0},  // mov w0, wzr
        {0x82bc8, 0x14000002},  // b function epilogue
        {0x82bcc, 0x12800000},  // mov w0, #-1
};

constexpr std::uintptr_t kCredentialLogTargetOffset = 0x15bd10;
constexpr std::uintptr_t kLegacyCeInitTargetOffset = 0x15c310;
constexpr std::uintptr_t kRejectedReturnOffset = 0x82bcc;
constexpr std::uintptr_t kAcceptedReturnOffset = 0x82bc4;
constexpr std::uintptr_t kVerifierEpilogueOffset = 0x82bd0;
constexpr std::size_t kMaxOemExecutableIntervals = 8;

void SecureWipe(void* data, std::size_t size) {
    volatile std::uint8_t* bytes = static_cast<volatile std::uint8_t*>(data);
    while (size != 0) {
        *bytes++ = 0;
        --size;
    }
}

bool HardenEarlyProcessState() {
    struct rlimit core_limit = {};
    if (setrlimit(RLIMIT_CORE, &core_limit) != 0) return false;
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) return false;
    // Close the small race where the parent exited before PDEATHSIG was armed.
    return getppid() != 1;
}

bool ParseFdName(const char* name, int* descriptor) {
    if (name == nullptr || descriptor == nullptr || *name == '\0') return false;
    unsigned long value = 0;
    for (const char* cursor = name; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return false;
        const unsigned int digit = static_cast<unsigned int>(*cursor - '0');
        if (value > (static_cast<unsigned long>(INT_MAX) - digit) / 10UL) {
            return false;
        }
        value = value * 10UL + digit;
    }
    *descriptor = static_cast<int>(value);
    return true;
}

bool CloseInheritedFileDescriptors() {
    const int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (null_fd < 0 || null_fd == protocol::kProtocolFd) {
        if (null_fd >= 0) close(null_fd);
        return false;
    }
    struct stat null_status = {};
    if (fstat(null_fd, &null_status) != 0 || !S_ISCHR(null_status.st_mode)) {
        close(null_fd);
        return false;
    }
    for (int descriptor = STDIN_FILENO; descriptor <= STDERR_FILENO;
         ++descriptor) {
        if (dup2(null_fd, descriptor) != descriptor) {
            if (null_fd > STDERR_FILENO) close(null_fd);
            return false;
        }
    }
    if (null_fd > STDERR_FILENO && close(null_fd) != 0) return false;

    DIR* directory = opendir("/proc/self/fd");
    if (directory == nullptr) return false;
    const int directory_fd = dirfd(directory);
    if (directory_fd < 0) {
        closedir(directory);
        return false;
    }

    bool success = true;
    while (success) {
        errno = 0;
        dirent* entry = readdir(directory);
        if (entry == nullptr) {
            success = errno == 0;
            break;
        }
        int descriptor = -1;
        if (!ParseFdName(entry->d_name, &descriptor) || descriptor <= STDERR_FILENO ||
            descriptor == protocol::kProtocolFd || descriptor == directory_fd) {
            continue;
        }
        if (close(descriptor) != 0 && errno != EBADF) success = false;
    }
    return closedir(directory) == 0 && success;
}

bool VerifyOemFileIdentity() {
    struct stat path_status = {};
    if (lstat(protocol::kOemLibraryPath, &path_status) != 0 ||
        !S_ISREG(path_status.st_mode) || path_status.st_size != kExpectedOemFileSize) {
        return false;
    }

    const int fd = open(protocol::kOemLibraryPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat file_status = {};
    if (fstat(fd, &file_status) != 0 || !S_ISREG(file_status.st_mode) ||
        file_status.st_size != kExpectedOemFileSize ||
        file_status.st_dev != path_status.st_dev ||
        file_status.st_ino != path_status.st_ino) {
        close(fd);
        return false;
    }

    void* mapping = mmap(nullptr, static_cast<std::size_t>(file_status.st_size),
                         PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapping == MAP_FAILED) return false;
    std::array<std::uint8_t, SHA256_DIGEST_LENGTH> digest = {};
    const unsigned char* hashed = SHA256(
            static_cast<const unsigned char*>(mapping),
            static_cast<std::size_t>(file_status.st_size), digest.data());
    munmap(mapping, static_cast<std::size_t>(file_status.st_size));

    unsigned int difference = hashed == nullptr ? 1U : 0U;
    for (std::size_t index = 0; index < digest.size(); ++index) {
        difference |= static_cast<unsigned int>(digest[index] ^ kExpectedOemSha256[index]);
    }
    SecureWipe(digest.data(), digest.size());
    return difference == 0;
}

bool SymbolHasExpectedOrigin(void* symbol, void* expected_base,
                             std::uintptr_t expected_offset) {
    if (symbol == nullptr || expected_base == nullptr) return false;
    Dl_info info = {};
    if (dladdr(symbol, &info) == 0 || info.dli_fbase != expected_base ||
        info.dli_fname == nullptr ||
        strcmp(info.dli_fname, protocol::kOemLibraryPath) != 0) {
        return false;
    }
    const std::uintptr_t symbol_address = reinterpret_cast<std::uintptr_t>(symbol);
    const std::uintptr_t base_address = reinterpret_cast<std::uintptr_t>(expected_base);
    return symbol_address >= base_address &&
           symbol_address - base_address == expected_offset;
}

std::uintptr_t DecodePcRelativeTarget(std::uintptr_t instruction_offset,
                                      std::uint32_t instruction,
                                      unsigned int immediate_shift,
                                      unsigned int immediate_bits) {
    const std::uint64_t mask = (1ULL << immediate_bits) - 1ULL;
    std::int64_t immediate =
            static_cast<std::int64_t>((instruction >> immediate_shift) & mask);
    const std::int64_t sign_bit = 1LL << (immediate_bits - 1);
    if ((immediate & sign_bit) != 0) immediate -= 1LL << immediate_bits;
    return static_cast<std::uintptr_t>(
            static_cast<std::int64_t>(instruction_offset) + immediate * 4);
}

bool VerifierOpcodeContextMatches(std::uintptr_t base, bool patched) {
    for (const OpcodeExpectation& expectation : kVerifierOpcodeContext) {
        std::uint32_t expected = expectation.original;
        if (patched && expectation.offset == kCredentialLogCallOffset) {
            expected = kAarch64Nop;
        } else if (patched && expectation.offset == kLegacyCeInitCallOffset) {
            expected = kAarch64MovW0One;
        }
        const std::uint32_t actual = *reinterpret_cast<const std::uint32_t*>(
                base + expectation.offset);
        if (actual != expected) return false;
    }

    const std::uint32_t rejected_branch = *reinterpret_cast<const std::uint32_t*>(
            base + 0x82bac);
    const std::uint32_t accepted_branch = *reinterpret_cast<const std::uint32_t*>(
            base + 0x82bb4);
    const std::uint32_t epilogue_branch = *reinterpret_cast<const std::uint32_t*>(
            base + 0x82bc8);
    if (DecodePcRelativeTarget(0x82bac, rejected_branch, 5, 19) !=
                kRejectedReturnOffset ||
        DecodePcRelativeTarget(0x82bb4, accepted_branch, 5, 14) !=
                kAcceptedReturnOffset ||
        DecodePcRelativeTarget(0x82bc8, epilogue_branch, 0, 26) !=
                kVerifierEpilogueOffset) {
        return false;
    }
    if (!patched) {
        const std::uint32_t credential_log =
                *reinterpret_cast<const std::uint32_t*>(
                        base + kCredentialLogCallOffset);
        const std::uint32_t legacy_ce_init =
                *reinterpret_cast<const std::uint32_t*>(
                        base + kLegacyCeInitCallOffset);
        if (DecodePcRelativeTarget(kCredentialLogCallOffset, credential_log, 0, 26) !=
                    kCredentialLogTargetOffset ||
            DecodePcRelativeTarget(kLegacyCeInitCallOffset, legacy_ce_init, 0, 26) !=
                    kLegacyCeInitTargetOffset) {
            return false;
        }
    }
    return true;
}

bool ApplyVerifierPatches(void* raw_base) {
    if (raw_base == nullptr) return false;
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(raw_base);
    std::uint32_t* credential_log = reinterpret_cast<std::uint32_t*>(
            base + kCredentialLogCallOffset);
    std::uint32_t* legacy_ce_init = reinterpret_cast<std::uint32_t*>(
            base + kLegacyCeInitCallOffset);
    if (!VerifierOpcodeContextMatches(base, false)) return false;

    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || (page_size & (page_size - 1)) != 0) return false;
    const std::uintptr_t page_mask = static_cast<std::uintptr_t>(page_size - 1);
    const std::uintptr_t start =
            reinterpret_cast<std::uintptr_t>(credential_log) & ~page_mask;
    const std::uintptr_t end =
            (reinterpret_cast<std::uintptr_t>(legacy_ce_init) + sizeof(std::uint32_t) +
             page_mask) &
            ~page_mask;
    if (end <= start || mprotect(reinterpret_cast<void*>(start), end - start,
                                 PROT_READ | PROT_WRITE) != 0) {
        return false;
    }

    *credential_log = kAarch64Nop;
    // OplusCredentialVerify still performs Gatekeeper verification. Only its
    // legacy empty-auth CE initializer is replaced; the TWRP parent performs
    // the real synthetic-password unwrap after this helper exits.
    *legacy_ce_init = kAarch64MovW0One;
    __builtin___clear_cache(reinterpret_cast<char*>(start),
                            reinterpret_cast<char*>(end));
    const bool restored =
            mprotect(reinterpret_cast<void*>(start), end - start,
                     PROT_READ | PROT_EXEC) == 0;
    return restored && VerifierOpcodeContextMatches(base, true);
}

alignas(16) unsigned char g_signal_stack[64 * 1024];
alignas(4) std::uint32_t g_stage =
        static_cast<std::uint32_t>(protocol::Stage::kStarting);
alignas(8) std::uint64_t g_attempt_id = 0;
alignas(8) std::uint64_t g_oem_load_base = 0;
alignas(8) std::uint64_t
        g_oem_executable_starts[kMaxOemExecutableIntervals] = {};
alignas(8) std::uint64_t
        g_oem_executable_ends[kMaxOemExecutableIntervals] = {};
alignas(4) std::uint32_t g_oem_executable_count = 0;
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

struct OemExecutableLayout {
    std::array<std::uint64_t, kMaxOemExecutableIntervals> starts = {};
    std::array<std::uint64_t, kMaxOemExecutableIntervals> ends = {};
    std::size_t count = 0;
    std::uintptr_t expected_base = 0;
    bool matched = false;
    bool invalid = false;
};

int CaptureOemExecutableLayout(struct dl_phdr_info* info, size_t, void* opaque) {
    OemExecutableLayout* layout = static_cast<OemExecutableLayout*>(opaque);
    if (info == nullptr || layout == nullptr ||
        static_cast<std::uintptr_t>(info->dlpi_addr) != layout->expected_base) {
        return 0;
    }
    layout->matched = true;
    if (info->dlpi_name == nullptr ||
        strcmp(info->dlpi_name, protocol::kOemLibraryPath) != 0) {
        layout->invalid = true;
        return 1;
    }

    for (ElfW(Half) index = 0; index < info->dlpi_phnum; ++index) {
        const ElfW(Phdr)& program_header = info->dlpi_phdr[index];
        if (program_header.p_type != PT_LOAD ||
            (program_header.p_flags & PF_X) == 0 ||
            program_header.p_memsz == 0) {
            continue;
        }
        const std::uint64_t start =
                static_cast<std::uint64_t>(program_header.p_vaddr);
        const std::uint64_t size =
                static_cast<std::uint64_t>(program_header.p_memsz);
        if (layout->count == layout->starts.size() ||
            start > std::numeric_limits<std::uint64_t>::max() - size) {
            layout->invalid = true;
            return 1;
        }
        layout->starts[layout->count] = start;
        layout->ends[layout->count] = start + size;
        ++layout->count;
    }
    return 1;
}

bool OffsetRangeInLayout(const OemExecutableLayout& layout, std::uint64_t offset,
                         std::uint64_t size) {
    if (size == 0 ||
        offset > std::numeric_limits<std::uint64_t>::max() - size) {
        return false;
    }
    const std::uint64_t end = offset + size;
    for (std::size_t index = 0; index < layout.count; ++index) {
        if (offset >= layout.starts[index] && end <= layout.ends[index]) return true;
    }
    return false;
}

bool InstallOemExecutableLayout(void* raw_base) {
    if (raw_base == nullptr) return false;
    OemExecutableLayout layout;
    layout.expected_base = reinterpret_cast<std::uintptr_t>(raw_base);
    dl_iterate_phdr(CaptureOemExecutableLayout, &layout);
    if (!layout.matched || layout.invalid || layout.count == 0) return false;

    for (std::size_t index = 1; index < layout.count; ++index) {
        const std::uint64_t start = layout.starts[index];
        const std::uint64_t end = layout.ends[index];
        std::size_t cursor = index;
        while (cursor != 0 && layout.starts[cursor - 1] > start) {
            layout.starts[cursor] = layout.starts[cursor - 1];
            layout.ends[cursor] = layout.ends[cursor - 1];
            --cursor;
        }
        layout.starts[cursor] = start;
        layout.ends[cursor] = end;
    }
    for (std::size_t index = 0; index < layout.count; ++index) {
        if (layout.ends[index] <= layout.starts[index] ||
            (index != 0 && layout.starts[index] < layout.ends[index - 1])) {
            return false;
        }
    }
    if (!OffsetRangeInLayout(layout, kVerifySymbolOffset, sizeof(std::uint32_t)) ||
        !OffsetRangeInLayout(layout, kCredentialLogCallOffset,
                             sizeof(std::uint32_t)) ||
        !OffsetRangeInLayout(layout, kLegacyCeInitCallOffset,
                             sizeof(std::uint32_t))) {
        return false;
    }

    StoreOemBase(layout.expected_base);
    for (std::size_t index = 0; index < layout.count; ++index) {
        __atomic_store_n(&g_oem_executable_starts[index], layout.starts[index],
                         __ATOMIC_RELAXED);
        __atomic_store_n(&g_oem_executable_ends[index], layout.ends[index],
                         __ATOMIC_RELAXED);
    }
    __atomic_store_n(&g_oem_executable_count,
                     static_cast<std::uint32_t>(layout.count), __ATOMIC_RELEASE);
    return true;
}

bool OemExecutableOffset(std::uint64_t address, std::uint64_t* offset) {
    if (offset == nullptr) return false;
    const std::uint32_t count =
            __atomic_load_n(&g_oem_executable_count, __ATOMIC_ACQUIRE);
    const std::uint64_t base = LoadOemBase();
    if (count == 0 || count > kMaxOemExecutableIntervals || base == 0 ||
        address < base) {
        return false;
    }
    const std::uint64_t relative = address - base;
    for (std::uint32_t index = 0; index < count; ++index) {
        const std::uint64_t start = __atomic_load_n(
                &g_oem_executable_starts[index], __ATOMIC_RELAXED);
        const std::uint64_t end = __atomic_load_n(
                &g_oem_executable_ends[index], __ATOMIC_RELAXED);
        if (relative >= start && relative < end) {
            *offset = relative;
            return true;
        }
    }
    return false;
}

bool SendReply(protocol::FrameType type, std::int32_t result, protocol::Stage stage) {
    protocol::ReplyFrame reply = {};
    reply.header = protocol::MakeHeader(type, sizeof(reply), LoadAttemptId());
    reply.result = result;
    reply.stage = static_cast<std::uint32_t>(stage);
    if (__atomic_load_n(&g_oem_executable_count, __ATOMIC_ACQUIRE) != 0) {
        reply.flags = protocol::kReplyOemIdentityVerified;
    }
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
#if defined(__aarch64__)
    if (raw_context != nullptr) {
        const ucontext_t* context = static_cast<const ucontext_t*>(raw_context);
        if (OemExecutableOffset(context->uc_mcontext.pc,
                                &crash.program_counter_offset)) {
            crash.address_flags |= protocol::kCrashPcOemExecutable;
        }
        if (OemExecutableOffset(context->uc_mcontext.regs[30],
                                &crash.link_register_offset)) {
            crash.address_flags |= protocol::kCrashLrOemExecutable;
        }
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
        SecureWipe(packet.data(), packet.size());
        return false;
    }

    const char* bytes = reinterpret_cast<const char*>(packet.data() + sizeof(frame));
    if (memchr(bytes, '\0', frame.credential_size) != nullptr) {
        SecureWipe(packet.data(), packet.size());
        return false;
    }
    credential->assign(bytes, frame.credential_size);
    SecureWipe(packet.data(), packet.size());
    return true;
}

void SecureWipeString(std::string* value) {
    if (value == nullptr) return;
    if (!value->empty()) SecureWipe(&(*value)[0], value->size());
    value->clear();
}

}  // namespace

int main() {
    if (!HardenEarlyProcessState()) return 2;
    if (!CloseInheritedFileDescriptors()) return 2;
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

    if (!VerifyOemFileIdentity()) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                            "stock OEM library identity mismatch");
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kOemIdentityMismatch),
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
    void* raw_setup_de_ce = nullptr;
    void* raw_get_password_type = nullptr;
    const VerifyFn verify = Resolve<VerifyFn>(handle, kVerifySymbol, &raw_verify);
    const SetupDeCeFn setup_de_ce =
            Resolve<SetupDeCeFn>(handle, kSetupDeCeSymbol, &raw_setup_de_ce);
    const GetPasswordTypeFn get_password_type =
            Resolve<GetPasswordTypeFn>(handle, kGetPasswordTypeSymbol,
                                       &raw_get_password_type);
    if (verify == nullptr || setup_de_ce == nullptr || get_password_type == nullptr) {
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kSymbolMissing),
               protocol::Stage::kStarting);
    }

    Dl_info library_info = {};
    if (dladdr(raw_verify, &library_info) == 0 || library_info.dli_fbase == nullptr ||
        !SymbolHasExpectedOrigin(raw_verify, library_info.dli_fbase,
                                 kVerifySymbolOffset) ||
        !SymbolHasExpectedOrigin(raw_setup_de_ce, library_info.dli_fbase,
                                 kSetupDeCeSymbolOffset) ||
        !SymbolHasExpectedOrigin(raw_get_password_type, library_info.dli_fbase,
                                 kGetPasswordTypeSymbolOffset)) {
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kOemIdentityMismatch),
               protocol::Stage::kStarting);
    }
    if (!InstallOemExecutableLayout(library_info.dli_fbase)) {
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kOemIdentityMismatch),
               protocol::Stage::kStarting);
    }
    StoreStage(protocol::Stage::kLibraryLoaded);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                        "exact stock OEM library loaded; keyring=%d",
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
    if (!ApplyVerifierPatches(library_info.dli_fbase)) {
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kBinaryPatchFailed),
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
    if (prctl(PR_SET_DUMPABLE, 0) != 0) {
        SecureWipeString(&credential);
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kIoFailed),
               protocol::Stage::kDePrepared);
    }
    if (!SendReply(protocol::FrameType::kVerifyStarted, 0,
                   protocol::Stage::kVerifyStarted)) {
        SecureWipeString(&credential);
        _exit(3);
    }
    StoreStage(protocol::Stage::kVerifyStarted);

    // Keep our source buffer owned across the by-value OEM ABI call so it can
    // be scrubbed deterministically instead of leaving a moved allocation.
    const int verify_result = verify(credential, 0);
    SecureWipeString(&credential);
    StoreStage(protocol::Stage::kVerifyReturned);
    if (verify_result == -1) {
        Finish(protocol::FrameType::kRejected, verify_result,
               protocol::Stage::kVerifyReturned);
    }
    if (verify_result != 0) {
        Finish(protocol::FrameType::kPreflightFailed,
               static_cast<std::int32_t>(protocol::Failure::kUnexpectedVerifyResult),
               protocol::Stage::kVerifyReturned);
    }
    StoreStage(protocol::Stage::kCredentialAccepted);
    Finish(protocol::FrameType::kAccepted, 0,
           protocol::Stage::kCredentialAccepted);
}
