#ifndef dash_pkc_ffi_SecretKey_HPP
#define dash_pkc_ffi_SecretKey_HPP

#include "SecretKey.d.hpp"

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
#include "PkcError.hpp"
#include "PublicKey.hpp"
#include "Scheme.hpp"
#include "SecretKeyVec.hpp"
#include "Signature.hpp"
#include "../../diplomat_runtime.hpp"


namespace dash_pkc::ffi {
namespace capi {
    extern "C" {

    typedef struct SecretKey_from_bytes_result {union {dash_pkc::ffi::capi::SecretKey* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} SecretKey_from_bytes_result;
    SecretKey_from_bytes_result SecretKey_from_bytes(diplomat::capi::DiplomatU8View bytes);

    typedef struct SecretKey_generate_result {union {dash_pkc::ffi::capi::SecretKey* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} SecretKey_generate_result;
    SecretKey_generate_result SecretKey_generate(diplomat::capi::DiplomatU8View ikm);

    typedef struct SecretKey_to_bytes_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} SecretKey_to_bytes_result;
    SecretKey_to_bytes_result SecretKey_to_bytes(const dash_pkc::ffi::capi::SecretKey* self, diplomat::capi::DiplomatU8ViewMut out);

    typedef struct SecretKey_public_key_result {union {dash_pkc::ffi::capi::PublicKey* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} SecretKey_public_key_result;
    SecretKey_public_key_result SecretKey_public_key(const dash_pkc::ffi::capi::SecretKey* self, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct SecretKey_sign_result {union {dash_pkc::ffi::capi::Signature* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} SecretKey_sign_result;
    SecretKey_sign_result SecretKey_sign(const dash_pkc::ffi::capi::SecretKey* self, diplomat::capi::DiplomatU8View msg, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct SecretKey_aggregate_result {union {dash_pkc::ffi::capi::SecretKey* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} SecretKey_aggregate_result;
    SecretKey_aggregate_result SecretKey_aggregate(const dash_pkc::ffi::capi::SecretKeyVec* keys);

    typedef struct SecretKey_derive_share_result {union {dash_pkc::ffi::capi::SecretKey* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} SecretKey_derive_share_result;
    SecretKey_derive_share_result SecretKey_derive_share(const dash_pkc::ffi::capi::SecretKeyVec* masters, diplomat::capi::DiplomatU8View id);

    typedef struct SecretKey_dh_exchange_result {union {dash_pkc::ffi::capi::PublicKey* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} SecretKey_dh_exchange_result;
    SecretKey_dh_exchange_result SecretKey_dh_exchange(const dash_pkc::ffi::capi::SecretKey* self, const dash_pkc::ffi::capi::PublicKey* peer);

    typedef struct SecretKey_ies_decrypt_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} SecretKey_ies_decrypt_result;
    SecretKey_ies_decrypt_result SecretKey_ies_decrypt(const dash_pkc::ffi::capi::SecretKey* self, const dash_pkc::ffi::capi::IesBlob* blob, size_t index, dash_pkc::ffi::capi::Scheme scheme, diplomat::capi::DiplomatU8ViewMut out);

    typedef struct SecretKey_ies_decrypt_multi_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} SecretKey_ies_decrypt_multi_result;
    SecretKey_ies_decrypt_multi_result SecretKey_ies_decrypt_multi(const dash_pkc::ffi::capi::SecretKey* self, const dash_pkc::ffi::capi::IesMultiBlob* blob, size_t index, dash_pkc::ffi::capi::Scheme scheme, diplomat::capi::DiplomatU8ViewMut out);

    dash_pkc::ffi::capi::SecretKey* SecretKey_boxed_clone(const dash_pkc::ffi::capi::SecretKey* self);

    bool SecretKey_eq(const dash_pkc::ffi::capi::SecretKey* self, const dash_pkc::ffi::capi::SecretKey* other);

    void SecretKey_destroy(SecretKey* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError> dash_pkc::ffi::SecretKey::from_bytes(diplomat::span<const uint8_t> bytes) {
    auto result = dash_pkc::ffi::capi::SecretKey_from_bytes({bytes.data(), bytes.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::SecretKey>>(std::unique_ptr<dash_pkc::ffi::SecretKey>(dash_pkc::ffi::SecretKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError> dash_pkc::ffi::SecretKey::generate(diplomat::span<const uint8_t> ikm) {
    auto result = dash_pkc::ffi::capi::SecretKey_generate({ikm.data(), ikm.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::SecretKey>>(std::unique_ptr<dash_pkc::ffi::SecretKey>(dash_pkc::ffi::SecretKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::SecretKey::to_bytes(diplomat::span<uint8_t> out) const {
    auto result = dash_pkc::ffi::capi::SecretKey_to_bytes(this->AsFFI(),
        {out.data(), out.size()});
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> dash_pkc::ffi::SecretKey::public_key(dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::SecretKey_public_key(this->AsFFI(),
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::PublicKey>>(std::unique_ptr<dash_pkc::ffi::PublicKey>(dash_pkc::ffi::PublicKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> dash_pkc::ffi::SecretKey::sign(diplomat::span<const uint8_t> msg, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::SecretKey_sign(this->AsFFI(),
        {msg.data(), msg.size()},
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::Signature>>(std::unique_ptr<dash_pkc::ffi::Signature>(dash_pkc::ffi::Signature::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError> dash_pkc::ffi::SecretKey::aggregate(const dash_pkc::ffi::SecretKeyVec& keys) {
    auto result = dash_pkc::ffi::capi::SecretKey_aggregate(keys.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::SecretKey>>(std::unique_ptr<dash_pkc::ffi::SecretKey>(dash_pkc::ffi::SecretKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError> dash_pkc::ffi::SecretKey::derive_share(const dash_pkc::ffi::SecretKeyVec& masters, diplomat::span<const uint8_t> id) {
    auto result = dash_pkc::ffi::capi::SecretKey_derive_share(masters.AsFFI(),
        {id.data(), id.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::SecretKey>>(std::unique_ptr<dash_pkc::ffi::SecretKey>(dash_pkc::ffi::SecretKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::SecretKey>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> dash_pkc::ffi::SecretKey::dh_exchange(const dash_pkc::ffi::PublicKey& peer) const {
    auto result = dash_pkc::ffi::capi::SecretKey_dh_exchange(this->AsFFI(),
        peer.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::PublicKey>>(std::unique_ptr<dash_pkc::ffi::PublicKey>(dash_pkc::ffi::PublicKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::SecretKey::ies_decrypt(const dash_pkc::ffi::IesBlob& blob, size_t index, dash_pkc::ffi::Scheme scheme, diplomat::span<uint8_t> out) const {
    auto result = dash_pkc::ffi::capi::SecretKey_ies_decrypt(this->AsFFI(),
        blob.AsFFI(),
        index,
        scheme.AsFFI(),
        {out.data(), out.size()});
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::SecretKey::ies_decrypt_multi(const dash_pkc::ffi::IesMultiBlob& blob, size_t index, dash_pkc::ffi::Scheme scheme, diplomat::span<uint8_t> out) const {
    auto result = dash_pkc::ffi::capi::SecretKey_ies_decrypt_multi(this->AsFFI(),
        blob.AsFFI(),
        index,
        scheme.AsFFI(),
        {out.data(), out.size()});
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline std::unique_ptr<dash_pkc::ffi::SecretKey> dash_pkc::ffi::SecretKey::clone() const {
    auto result = dash_pkc::ffi::capi::SecretKey_boxed_clone(this->AsFFI());
    return std::unique_ptr<dash_pkc::ffi::SecretKey>(dash_pkc::ffi::SecretKey::FromFFI(result));
}

inline bool dash_pkc::ffi::SecretKey::eq(const dash_pkc::ffi::SecretKey& other) const {
    auto result = dash_pkc::ffi::capi::SecretKey_eq(this->AsFFI(),
        other.AsFFI());
    return result;
}

inline const dash_pkc::ffi::capi::SecretKey* dash_pkc::ffi::SecretKey::AsFFI() const {
    return reinterpret_cast<const dash_pkc::ffi::capi::SecretKey*>(this);
}

inline dash_pkc::ffi::capi::SecretKey* dash_pkc::ffi::SecretKey::AsFFI() {
    return reinterpret_cast<dash_pkc::ffi::capi::SecretKey*>(this);
}

inline const dash_pkc::ffi::SecretKey* dash_pkc::ffi::SecretKey::FromFFI(const dash_pkc::ffi::capi::SecretKey* ptr) {
    return reinterpret_cast<const dash_pkc::ffi::SecretKey*>(ptr);
}

inline dash_pkc::ffi::SecretKey* dash_pkc::ffi::SecretKey::FromFFI(dash_pkc::ffi::capi::SecretKey* ptr) {
    return reinterpret_cast<dash_pkc::ffi::SecretKey*>(ptr);
}

inline void dash_pkc::ffi::SecretKey::operator delete(void* ptr) {
    dash_pkc::ffi::capi::SecretKey_destroy(reinterpret_cast<dash_pkc::ffi::capi::SecretKey*>(ptr));
}


#endif // dash_pkc_ffi_SecretKey_HPP
