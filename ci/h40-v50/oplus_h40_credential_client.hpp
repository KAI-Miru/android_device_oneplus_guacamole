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
// filesystem path. kRejected means the exact OEM verifier returned -1 and no
// modern handoff occurred; ambiguous or malformed outcomes are process-lifetime
// fatal to the adapter.
// kAccepted proves only the OEM credential gate: V5.0 deliberately suppresses
// the stock legacy CE initializer and requires a separate modern-SP handoff.
IsolatedVerifyResult VerifyCredentialIsolated(const std::string& credential,
                                               int expected_password_type);

}  // namespace oplus_h40
}  // namespace twrp
