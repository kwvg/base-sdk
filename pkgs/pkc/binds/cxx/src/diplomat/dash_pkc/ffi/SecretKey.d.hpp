#ifndef dash_pkc_ffi_SecretKey_D_HPP
#define dash_pkc_ffi_SecretKey_D_HPP

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
namespace capi { struct IesBlob; }
class IesBlob;
namespace capi { struct IesMultiBlob; }
class IesMultiBlob;
namespace capi { struct PublicKey; }
class PublicKey;
namespace capi { struct SecretKey; }
class SecretKey;
namespace capi { struct SecretKeyVec; }
class SecretKeyVec;
namespace capi { struct Signature; }
class Signature;
class PkcError;
class Scheme;
} // namespace dash_pkc::ffi




namespace dash_pkc::ffi {
namespace capi {
    struct SecretKey;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * A BLS12-381 secret key (32 bytes, big-endian scalar).
 *
 * Secret scalars are scheme independent; scheme selection
 * happens per operation (`sign`, `public_key`).
 */
class SecretKey {
public:

  /**
   * Parse a 32-byte big-endian scalar; rejects zero and values
   * not below the group order.
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError> from_bytes(diplomat::span<const uint8_t> bytes);

  /**
   * Derive a key from at least 32 bytes of seed material
   * (dashbls EIP-2333 v3 KeyGen).
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError> generate(diplomat::span<const uint8_t> ikm);

  /**
   * Write the 32-byte big-endian scalar into `out`.
   */
  inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> to_bytes(diplomat::span<uint8_t> out) const;

  /**
   * Derive the public key, tagged with `scheme`.
   */
  inline diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> public_key(dash_pkc::ffi::Scheme scheme) const;

  /**
   * Sign `msg` under `scheme`. Legacy signing requires a
   * 32-byte message (a hash), matching dashbls.
   */
  inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> sign(diplomat::span<const uint8_t> msg, dash_pkc::ffi::Scheme scheme) const;

  /**
   * Sum the collected keys mod the group order (dashbls
   * `PrivateKey::Aggregate`).
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError> aggregate(const dash_pkc::ffi::SecretKeyVec& keys);

  /**
   * Evaluate the secret polynomial `masters` at the 32-byte
   * participant `id` (dashbls `Threshold::PrivateKeyShare`).
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError> derive_share(const dash_pkc::ffi::SecretKeyVec& masters, diplomat::span<const uint8_t> id);

  /**
   * Diffie-Hellman exchange `self * peer`; the result carries
   * the peer's scheme tag.
   */
  inline diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> dh_exchange(const dash_pkc::ffi::PublicKey& peer) const;

  /**
   * Decrypt a single-recipient blob whose ephemeral key was
   * serialized under `scheme`. `out` must be exactly
   * `blob.data_len()` bytes (CBC keeps lengths).
   */
  inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> ies_decrypt(const dash_pkc::ffi::IesBlob& blob, size_t index, dash_pkc::ffi::Scheme scheme, diplomat::span<uint8_t> out) const;

  /**
   * Decrypt one recipient's slot of a multi-recipient blob
   * whose ephemeral key was serialized under `scheme`. `out`
   * must be exactly `blob.data_len_at(index)` bytes.
   */
  inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> ies_decrypt_multi(const dash_pkc::ffi::IesMultiBlob& blob, size_t index, dash_pkc::ffi::Scheme scheme, diplomat::span<uint8_t> out) const;

  /**
   * Deep copy for C++ value semantics.
   */
  inline std::unique_ptr<dash_pkc::ffi::SecretKey> clone() const;

  /**
   * Constant-time equality.
   */
  inline bool eq(const dash_pkc::ffi::SecretKey& other) const;

    inline const dash_pkc::ffi::capi::SecretKey* AsFFI() const;
    inline dash_pkc::ffi::capi::SecretKey* AsFFI();
    inline static const dash_pkc::ffi::SecretKey* FromFFI(const dash_pkc::ffi::capi::SecretKey* ptr);
    inline static dash_pkc::ffi::SecretKey* FromFFI(dash_pkc::ffi::capi::SecretKey* ptr);
    inline static void operator delete(void* ptr);
private:
    SecretKey() = delete;
    SecretKey(const dash_pkc::ffi::SecretKey&) = delete;
    SecretKey(dash_pkc::ffi::SecretKey&&) noexcept = delete;
    SecretKey operator=(const dash_pkc::ffi::SecretKey&) = delete;
    SecretKey operator=(dash_pkc::ffi::SecretKey&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // dash_pkc_ffi_SecretKey_D_HPP
