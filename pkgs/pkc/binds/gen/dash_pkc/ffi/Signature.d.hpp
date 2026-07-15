#ifndef dash_pkc_ffi_Signature_D_HPP
#define dash_pkc_ffi_Signature_D_HPP

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "../../diplomat_runtime.hpp"

namespace dash_pkc::ffi {
namespace capi { struct IdVec; }
class IdVec;
namespace capi { struct MessageVec; }
class MessageVec;
namespace capi { struct PublicKey; }
class PublicKey;
namespace capi { struct PublicKeyVec; }
class PublicKeyVec;
namespace capi { struct Signature; }
class Signature;
namespace capi { struct SignatureVec; }
class SignatureVec;
class PkcError;
class Scheme;
} // namespace dash_pkc::ffi




namespace dash_pkc::ffi {
namespace capi {
    struct Signature;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * A G2 signature (96 bytes compressed), scheme-tagged.
 */
class Signature {
public:

  /**
   * Parse 96 compressed bytes under `scheme`. Rejects
   * infinity and non-subgroup points.
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> from_bytes(diplomat::span<const uint8_t> bytes, dash_pkc::ffi::Scheme scheme);

  /**
   * Write the 96-byte compressed form under `scheme` into
   * `out`, converting representations when they differ.
   */
  inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> to_bytes(diplomat::span<uint8_t> out, dash_pkc::ffi::Scheme scheme) const;

  /**
   * The scheme this element was parsed or derived under.
   */
  inline dash_pkc::ffi::Scheme scheme() const;

  /**
   * Deep copy for C++ value semantics.
   */
  inline std::unique_ptr<dash_pkc::ffi::Signature> clone() const;

  /**
   * Group element equality across scheme tags.
   */
  inline bool eq(const dash_pkc::ffi::Signature& other) const;

  /**
   * Verify against a single key and message under `scheme`
   * (dashbls `CoreMPL::Verify`).
   */
  inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> verify(diplomat::span<const uint8_t> msg, const dash_pkc::ffi::PublicKey& pk, dash_pkc::ffi::Scheme scheme) const;

  /**
   * Sum the collected signatures (dashbls
   * `CoreMPL::Aggregate`).
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> aggregate(const dash_pkc::ffi::SignatureVec& sigs, dash_pkc::ffi::Scheme scheme);

  /**
   * Aggregate same-message signatures with public-key-weighted
   * delinearization (dashbls `CoreMPL::AggregateSecure`).
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> aggregate_secure(const dash_pkc::ffi::SignatureVec& sigs, const dash_pkc::ffi::PublicKeyVec& pks, dash_pkc::ffi::Scheme scheme);

  /**
   * Verify a secure-aggregated same-message signature (dashbls
   * `CoreMPL::VerifySecure`).
   */
  inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> verify_secure(const dash_pkc::ffi::PublicKeyVec& pks, diplomat::span<const uint8_t> msg, dash_pkc::ffi::Scheme scheme) const;

  /**
   * Verify an aggregate over per-signer messages (dashbls
   * `CoreMPL::AggregateVerify`). Basic enforces distinct
   * messages; legacy does not, matching dashbls.
   */
  inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> verify_aggregated(const dash_pkc::ffi::MessageVec& msgs, const dash_pkc::ffi::PublicKeyVec& pks, dash_pkc::ffi::Scheme scheme) const;

  /**
   * Subtract `other` from this aggregate: `self + (-other)`
   * (Dash Core `CBLSSignature::SubInsecure`).
   */
  inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> sub_insecure(const dash_pkc::ffi::Signature& other) const;

  /**
   * Recover a threshold signature from id-tagged shares via
   * Lagrange interpolation (dashbls
   * `Threshold::SignatureRecover`).
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> recover(const dash_pkc::ffi::SignatureVec& sigs, const dash_pkc::ffi::IdVec& ids, dash_pkc::ffi::Scheme scheme);

    inline const dash_pkc::ffi::capi::Signature* AsFFI() const;
    inline dash_pkc::ffi::capi::Signature* AsFFI();
    inline static const dash_pkc::ffi::Signature* FromFFI(const dash_pkc::ffi::capi::Signature* ptr);
    inline static dash_pkc::ffi::Signature* FromFFI(dash_pkc::ffi::capi::Signature* ptr);
    inline static void operator delete(void* ptr);
private:
    Signature() = delete;
    Signature(const dash_pkc::ffi::Signature&) = delete;
    Signature(dash_pkc::ffi::Signature&&) noexcept = delete;
    Signature operator=(const dash_pkc::ffi::Signature&) = delete;
    Signature operator=(dash_pkc::ffi::Signature&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // dash_pkc_ffi_Signature_D_HPP
