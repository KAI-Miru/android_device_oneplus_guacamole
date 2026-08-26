#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace twrp {
namespace oplus_h40 {
namespace credential_protocol {

constexpr char kHelperPath[] = "/system/bin/oplus_h40_credential_helper";
constexpr char kOemLibraryPath[] = "/system/lib64/libdecrypt_recovery.so";
constexpr int kProtocolFd = 3;
constexpr std::uint32_t kMagic = 0x30433548;  // "H5C0" in little endian.
constexpr std::uint16_t kVersion = 3;
constexpr std::uint32_t kMaxCredentialBytes = 1024;
constexpr std::uint32_t kReplyOemIdentityVerified = 1U << 0;
constexpr std::uint32_t kKnownReplyFlags = kReplyOemIdentityVerified;
constexpr std::uint32_t kCrashPcOemExecutable = 1U << 0;
constexpr std::uint32_t kCrashLrOemExecutable = 1U << 1;
constexpr std::uint32_t kKnownCrashAddressFlags =
        kCrashPcOemExecutable | kCrashLrOemExecutable;

enum class FrameType : std::uint16_t {
    kHello = 1,
    kReady = 2,
    kCredential = 3,
    kVerifyStarted = 4,
    kAccepted = 5,
    kRejected = 6,
    kPreflightFailed = 7,
    kCrashed = 8,
};

enum class Stage : std::uint32_t {
    kStarting = 1,
    kLibraryLoaded = 2,
    kDePrepared = 3,
    kVerifyStarted = 4,
    kVerifyReturned = 5,
    kCredentialAccepted = 6,
};

enum class Failure : std::int32_t {
    kInvalidFrame = 1,
    kSessionKeyringUnavailable = 2,
    kLibraryLoadFailed = 3,
    kSymbolMissing = 4,
    kSetupDeCeFailed = 5,
    kPasswordTypeInvalid = 6,
    kDeLayoutInvalid = 7,
    kOemIdentityMismatch = 8,
    kBinaryPatchFailed = 9,
    kIoFailed = 10,
    kUnexpectedVerifyResult = 11,
};

struct FrameHeader {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t type;
    std::uint32_t frame_size;
    std::uint32_t reserved;
    std::uint64_t attempt_id;
};

struct HelloFrame {
    FrameHeader header;
    std::int32_t user_id;
    std::int32_t expected_password_type;
};

struct CredentialFrame {
    FrameHeader header;
    std::int32_t user_id;
    std::uint32_t credential_size;
    // credential_size bytes immediately follow in the same SOCK_SEQPACKET record.
};

struct ReplyFrame {
    FrameHeader header;
    std::int32_t result;
    std::uint32_t stage;
    std::uint32_t flags;
    std::uint32_t reserved;
};

struct CrashFrame {
    FrameHeader header;
    std::int32_t signal_number;
    std::uint32_t stage;
    std::int32_t signal_code;
    std::uint32_t crashing_tid;
    std::uint64_t program_counter_offset;
    std::uint64_t link_register_offset;
    std::uint32_t address_flags;
    std::uint32_t reserved;
};

static_assert(sizeof(FrameHeader) == 24, "unexpected H.40 V5.0 frame-header ABI");
static_assert(sizeof(HelloFrame) == 32, "unexpected H.40 V5.0 hello ABI");
static_assert(sizeof(CredentialFrame) == 32, "unexpected H.40 V5.0 credential ABI");
static_assert(sizeof(ReplyFrame) == 40, "unexpected H.40 V5.0 reply ABI");
static_assert(sizeof(CrashFrame) == 64, "unexpected H.40 V5.0 crash ABI");
static_assert(std::is_trivially_copyable<FrameHeader>::value, "frame header must be POD");
static_assert(std::is_trivially_copyable<HelloFrame>::value, "hello frame must be POD");
static_assert(std::is_trivially_copyable<CredentialFrame>::value,
              "credential frame must be POD");
static_assert(std::is_trivially_copyable<ReplyFrame>::value, "reply frame must be POD");
static_assert(std::is_trivially_copyable<CrashFrame>::value, "crash frame must be POD");

inline FrameHeader MakeHeader(FrameType type, std::uint32_t size,
                              std::uint64_t attempt_id) {
    FrameHeader header = {};
    header.magic = kMagic;
    header.version = kVersion;
    header.type = static_cast<std::uint16_t>(type);
    header.frame_size = size;
    header.attempt_id = attempt_id;
    return header;
}

inline bool HeaderMatches(const FrameHeader& header, FrameType type,
                          std::uint32_t size, std::uint64_t attempt_id) {
    return header.magic == kMagic && header.version == kVersion &&
           header.type == static_cast<std::uint16_t>(type) &&
           header.frame_size == size && header.reserved == 0 &&
           header.attempt_id == attempt_id;
}

}  // namespace credential_protocol
}  // namespace oplus_h40
}  // namespace twrp
