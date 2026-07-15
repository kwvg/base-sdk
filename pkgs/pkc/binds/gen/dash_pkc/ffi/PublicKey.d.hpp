#ifndef dash_pkc_ffi_PublicKey_D_HPP
#define dash_pkc_ffi_PublicKey_D_HPP

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
namespace capi { struct MessageVec; }
class MessageVec;
namespace capi { struct PublicKey; }
class PublicKey;
namespace capi { struct PublicKeyVec; }
class PublicKeyVec;
class PkcError;
class Scheme;
} // namespace dash_pkc::ffi




namespace dash_pkc::ffi {
namespace capi {
    struct PublicKey;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * A G1 public key (48 bytes compressed), scheme-tagged.
 */
class PublicKey {
public:

  /**
   * Parse 48 compressed bytes under `scheme`. Rejects
   * infinity and non-subgroup points.
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> from_bytes(diplomat::span<const uint8_t> bytes, dash_pkc::ffi::Scheme scheme);

  /**
   * Write the 48-byte compressed form under `scheme` into
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
  inline std::unique_ptr<dash_pkc::ffi::PublicKey> clone() const;

  /**
   * Group element equality across scheme tags.
   */
  inline bool eq(const dash_pkc::ffi::PublicKey& other) const;

  /**
   * Sum the collected keys (dashbls `CoreMPL::Aggregate`).
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> aggregate(const dash_pkc::ffi::PublicKeyVec& keys, dash_pkc::ffi::Scheme scheme);

  /**
   * Evaluate the public polynomial `masters` at the 32-byte
   * participant `id` (dashbls `Threshold::PublicKeyShare`).
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> derive_share(const dash_pkc::ffi::PublicKeyVec& masters, diplomat::span<const uint8_t> id, dash_pkc::ffi::Scheme scheme);

  /**
   * BLS-IES encrypt `plaintext` (length a multiple of 16) to
   * this key. `entropy` must supply at least 64 random bytes.
   */
  inline diplomat::result<std::unique_ptr<dash_pkc::ffi::IesBlob>, dash_pkc::ffi::PkcError> ies_encrypt(diplomat::span<const uint8_t> plaintext, diplomat::span<const uint8_t> entropy) const;

  /**
   * BLS-IES encrypt one plaintext per recipient under a shared
   * ephemeral key. `entropy` must supply at least 64 random
   * bytes.
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::IesMultiBlob>, dash_pkc::ffi::PkcError> ies_encrypt_multi(const dash_pkc::ffi::PublicKeyVec& recipients, const dash_pkc::ffi::MessageVec& plaintexts, diplomat::span<const uint8_t> entropy, dash_pkc::ffi::Scheme scheme);

    inline const dash_pkc::ffi::capi::PublicKey* AsFFI() const;
    inline dash_pkc::ffi::capi::PublicKey* AsFFI();
    inline static const dash_pkc::ffi::PublicKey* FromFFI(const dash_pkc::ffi::capi::PublicKey* ptr);
    inline static dash_pkc::ffi::PublicKey* FromFFI(dash_pkc::ffi::capi::PublicKey* ptr);
    inline static void operator delete(void* ptr);
private:
    PublicKey() = delete;
    PublicKey(const dash_pkc::ffi::PublicKey&) = delete;
    PublicKey(dash_pkc::ffi::PublicKey&&) noexcept = delete;
    PublicKey operator=(const dash_pkc::ffi::PublicKey&) = delete;
    PublicKey operator=(dash_pkc::ffi::PublicKey&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // dash_pkc_ffi_PublicKey_D_HPP
