#pragma once

#include <string>

namespace twrp {
namespace oplus_h40 {

enum class IsolatedVerifyResult {
    kAccepted,
    kRejected,
    kFatalFailure,
};

// Executes the OEM credential verifier in a fresh /system/bin process using
// H.40's stock linker namespace. No credential is placed in argv, env, or a
// filesystem path. kRejected is returned only for a normal OEM rejection;
// ambiguous or malformed outcomes are process-lifetime fatal to the adapter.
IsolatedVerifyResult VerifyCredentialIsolated(const std::string& credential,
                                               int expected_password_type);

}  // namespace oplus_h40
}  // namespace twrp
