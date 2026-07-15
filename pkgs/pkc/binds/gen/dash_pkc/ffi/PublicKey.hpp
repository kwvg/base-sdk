#ifndef dash_pkc_ffi_PublicKey_HPP
#define dash_pkc_ffi_PublicKey_HPP

#include "PublicKey.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "IesBlob.hpp"
#include "IesMultiBlob.hpp"
#include "MessageVec.hpp"
#include "PkcError.hpp"
#include "PublicKeyVec.hpp"
#include "Scheme.hpp"
#include "../../diplomat_runtime.hpp"


namespace dash_pkc::ffi {
namespace capi {
    extern "C" {

    typedef struct PublicKey_from_bytes_result {union {dash_pkc::ffi::capi::PublicKey* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} PublicKey_from_bytes_result;
    PublicKey_from_bytes_result PublicKey_from_bytes(diplomat::capi::DiplomatU8View bytes, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct PublicKey_to_bytes_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} PublicKey_to_bytes_result;
    PublicKey_to_bytes_result PublicKey_to_bytes(const dash_pkc::ffi::capi::PublicKey* self, diplomat::capi::DiplomatU8ViewMut out, dash_pkc::ffi::capi::Scheme scheme);

    dash_pkc::ffi::capi::Scheme PublicKey_scheme(const dash_pkc::ffi::capi::PublicKey* self);

    dash_pkc::ffi::capi::PublicKey* PublicKey_boxed_clone(const dash_pkc::ffi::capi::PublicKey* self);

    bool PublicKey_eq(const dash_pkc::ffi::capi::PublicKey* self, const dash_pkc::ffi::capi::PublicKey* other);

    typedef struct PublicKey_aggregate_result {union {dash_pkc::ffi::capi::PublicKey* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} PublicKey_aggregate_result;
    PublicKey_aggregate_result PublicKey_aggregate(const dash_pkc::ffi::capi::PublicKeyVec* keys, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct PublicKey_derive_share_result {union {dash_pkc::ffi::capi::PublicKey* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} PublicKey_derive_share_result;
    PublicKey_derive_share_result PublicKey_derive_share(const dash_pkc::ffi::capi::PublicKeyVec* masters, diplomat::capi::DiplomatU8View id, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct PublicKey_ies_encrypt_result {union {dash_pkc::ffi::capi::IesBlob* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} PublicKey_ies_encrypt_result;
    PublicKey_ies_encrypt_result PublicKey_ies_encrypt(const dash_pkc::ffi::capi::PublicKey* self, diplomat::capi::DiplomatU8View plaintext, diplomat::capi::DiplomatU8View entropy);

    typedef struct PublicKey_ies_encrypt_multi_result {union {dash_pkc::ffi::capi::IesMultiBlob* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} PublicKey_ies_encrypt_multi_result;
    PublicKey_ies_encrypt_multi_result PublicKey_ies_encrypt_multi(const dash_pkc::ffi::capi::PublicKeyVec* recipients, const dash_pkc::ffi::capi::MessageVec* plaintexts, diplomat::capi::DiplomatU8View entropy, dash_pkc::ffi::capi::Scheme scheme);

    void PublicKey_destroy(PublicKey* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> dash_pkc::ffi::PublicKey::from_bytes(diplomat::span<const uint8_t> bytes, dash_pkc::ffi::Scheme scheme) {
    auto result = dash_pkc::ffi::capi::PublicKey_from_bytes({bytes.data(), bytes.size()},
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::PublicKey>>(std::unique_ptr<dash_pkc::ffi::PublicKey>(dash_pkc::ffi::PublicKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::PublicKey::to_bytes(diplomat::span<uint8_t> out, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::PublicKey_to_bytes(this->AsFFI(),
        {out.data(), out.size()},
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline dash_pkc::ffi::Scheme dash_pkc::ffi::PublicKey::scheme() const {
    auto result = dash_pkc::ffi::capi::PublicKey_scheme(this->AsFFI());
    return dash_pkc::ffi::Scheme::FromFFI(result);
}

inline std::unique_ptr<dash_pkc::ffi::PublicKey> dash_pkc::ffi::PublicKey::clone() const {
    auto result = dash_pkc::ffi::capi::PublicKey_boxed_clone(this->AsFFI());
    return std::unique_ptr<dash_pkc::ffi::PublicKey>(dash_pkc::ffi::PublicKey::FromFFI(result));
}

inline bool dash_pkc::ffi::PublicKey::eq(const dash_pkc::ffi::PublicKey& other) const {
    auto result = dash_pkc::ffi::capi::PublicKey_eq(this->AsFFI(),
        other.AsFFI());
    return result;
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> dash_pkc::ffi::PublicKey::aggregate(const dash_pkc::ffi::PublicKeyVec& keys, dash_pkc::ffi::Scheme scheme) {
    auto result = dash_pkc::ffi::capi::PublicKey_aggregate(keys.AsFFI(),
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::PublicKey>>(std::unique_ptr<dash_pkc::ffi::PublicKey>(dash_pkc::ffi::PublicKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> dash_pkc::ffi::PublicKey::derive_share(const dash_pkc::ffi::PublicKeyVec& masters, diplomat::span<const uint8_t> id, dash_pkc::ffi::Scheme scheme) {
    auto result = dash_pkc::ffi::capi::PublicKey_derive_share(masters.AsFFI(),
        {id.data(), id.size()},
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::PublicKey>>(std::unique_ptr<dash_pkc::ffi::PublicKey>(dash_pkc::ffi::PublicKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::IesBlob>, dash_pkc::ffi::PkcError> dash_pkc::ffi::PublicKey::ies_encrypt(diplomat::span<const uint8_t> plaintext, diplomat::span<const uint8_t> entropy) const {
    auto result = dash_pkc::ffi::capi::PublicKey_ies_encrypt(this->AsFFI(),
        {plaintext.data(), plaintext.size()},
        {entropy.data(), entropy.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::IesBlob>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::IesBlob>>(std::unique_ptr<dash_pkc::ffi::IesBlob>(dash_pkc::ffi::IesBlob::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::IesBlob>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::IesMultiBlob>, dash_pkc::ffi::PkcError> dash_pkc::ffi::PublicKey::ies_encrypt_multi(const dash_pkc::ffi::PublicKeyVec& recipients, const dash_pkc::ffi::MessageVec& plaintexts, diplomat::span<const uint8_t> entropy, dash_pkc::ffi::Scheme scheme) {
    auto result = dash_pkc::ffi::capi::PublicKey_ies_encrypt_multi(recipients.AsFFI(),
        plaintexts.AsFFI(),
        {entropy.data(), entropy.size()},
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::IesMultiBlob>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::IesMultiBlob>>(std::unique_ptr<dash_pkc::ffi::IesMultiBlob>(dash_pkc::ffi::IesMultiBlob::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::IesMultiBlob>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline const dash_pkc::ffi::capi::PublicKey* dash_pkc::ffi::PublicKey::AsFFI() const {
    return reinterpret_cast<const dash_pkc::ffi::capi::PublicKey*>(this);
}

inline dash_pkc::ffi::capi::PublicKey* dash_pkc::ffi::PublicKey::AsFFI() {
    return reinterpret_cast<dash_pkc::ffi::capi::PublicKey*>(this);
}

inline const dash_pkc::ffi::PublicKey* dash_pkc::ffi::PublicKey::FromFFI(const dash_pkc::ffi::capi::PublicKey* ptr) {
    return reinterpret_cast<const dash_pkc::ffi::PublicKey*>(ptr);
}

inline dash_pkc::ffi::PublicKey* dash_pkc::ffi::PublicKey::FromFFI(dash_pkc::ffi::capi::PublicKey* ptr) {
    return reinterpret_cast<dash_pkc::ffi::PublicKey*>(ptr);
}

inline void dash_pkc::ffi::PublicKey::operator delete(void* ptr) {
    dash_pkc::ffi::capi::PublicKey_destroy(reinterpret_cast<dash_pkc::ffi::capi::PublicKey*>(ptr));
}


#endif // dash_pkc_ffi_PublicKey_HPP
