#ifndef dash_pkc_ffi_Session_D_HPP
#define dash_pkc_ffi_Session_D_HPP

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
namespace capi { struct Session; }
class Session;
namespace capi { struct Signature; }
class Signature;
namespace capi { struct SignatureVec; }
class SignatureVec;
class PkcError;
class Scheme;
} // namespace dash_pkc::ffi




namespace dash_pkc::ffi {
namespace capi {
    struct Session;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * Program-lifetime crypto context (libsecp256k1-style): owns all
 * runtime caches and the keyed-hash entropy. Create once at
 * application init with strong entropy; operations routed
 * through a session use its caches, plain operations never do.
 */
class Session {
public:

  /**
   * Create a session from at least 32 bytes of entropy.
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::Session>, dash_pkc::ffi::PkcError> create(diplomat::span<const uint8_t> entropy);

  /**
   * As `Signature::verify`, using the session's hash-to-G2
   * cache for 32-byte messages.
   */
  inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> verify(const dash_pkc::ffi::Signature& sig, diplomat::span<const uint8_t> msg, const dash_pkc::ffi::PublicKey& pk, dash_pkc::ffi::Scheme scheme) const;

  /**
   * As `Signature::verify_aggregated`, using the session's
   * hash-to-G2 cache when all messages are 32 bytes.
   */
  inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> verify_aggregated(const dash_pkc::ffi::Signature& sig, const dash_pkc::ffi::MessageVec& msgs, const dash_pkc::ffi::PublicKeyVec& pks, dash_pkc::ffi::Scheme scheme) const;

  /**
   * As `Signature::verify_secure`; cache-accelerated variants
   * are introduced per technique.
   */
  inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> verify_secure(const dash_pkc::ffi::Signature& sig, const dash_pkc::ffi::PublicKeyVec& pks, diplomat::span<const uint8_t> msg, dash_pkc::ffi::Scheme scheme) const;

  /**
   * As `Signature::aggregate_secure`.
   */
  inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> aggregate_secure(const dash_pkc::ffi::SignatureVec& sigs, const dash_pkc::ffi::PublicKeyVec& pks, dash_pkc::ffi::Scheme scheme) const;

  /**
   * As `PublicKey::from_bytes`.
   */
  inline diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> parse_public_key(diplomat::span<const uint8_t> bytes, dash_pkc::ffi::Scheme scheme) const;

  /**
   * As `Signature::from_bytes`.
   */
  inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> parse_signature(diplomat::span<const uint8_t> bytes, dash_pkc::ffi::Scheme scheme) const;

  /**
   * As `PublicKey::derive_share`.
   */
  inline diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> public_key_share(const dash_pkc::ffi::PublicKeyVec& masters, diplomat::span<const uint8_t> id, dash_pkc::ffi::Scheme scheme) const;

  /**
   * As `Signature::recover`.
   */
  inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> recover_signature(const dash_pkc::ffi::SignatureVec& sigs, const dash_pkc::ffi::IdVec& ids, dash_pkc::ffi::Scheme scheme) const;

    inline const dash_pkc::ffi::capi::Session* AsFFI() const;
    inline dash_pkc::ffi::capi::Session* AsFFI();
    inline static const dash_pkc::ffi::Session* FromFFI(const dash_pkc::ffi::capi::Session* ptr);
    inline static dash_pkc::ffi::Session* FromFFI(dash_pkc::ffi::capi::Session* ptr);
    inline static void operator delete(void* ptr);
private:
    Session() = delete;
    Session(const dash_pkc::ffi::Session&) = delete;
    Session(dash_pkc::ffi::Session&&) noexcept = delete;
    Session operator=(const dash_pkc::ffi::Session&) = delete;
    Session operator=(dash_pkc::ffi::Session&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // dash_pkc_ffi_Session_D_HPP
