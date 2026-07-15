#ifndef dash_pkc_ffi_Signature_HPP
#define dash_pkc_ffi_Signature_HPP

#include "Signature.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "IdVec.hpp"
#include "MessageVec.hpp"
#include "PkcError.hpp"
#include "PublicKey.hpp"
#include "PublicKeyVec.hpp"
#include "Scheme.hpp"
#include "SignatureVec.hpp"
#include "../../diplomat_runtime.hpp"


namespace dash_pkc::ffi {
namespace capi {
    extern "C" {

    typedef struct Signature_from_bytes_result {union {dash_pkc::ffi::capi::Signature* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Signature_from_bytes_result;
    Signature_from_bytes_result Signature_from_bytes(diplomat::capi::DiplomatU8View bytes, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Signature_to_bytes_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Signature_to_bytes_result;
    Signature_to_bytes_result Signature_to_bytes(const dash_pkc::ffi::capi::Signature* self, diplomat::capi::DiplomatU8ViewMut out, dash_pkc::ffi::capi::Scheme scheme);

    dash_pkc::ffi::capi::Scheme Signature_scheme(const dash_pkc::ffi::capi::Signature* self);

    dash_pkc::ffi::capi::Signature* Signature_boxed_clone(const dash_pkc::ffi::capi::Signature* self);

    bool Signature_eq(const dash_pkc::ffi::capi::Signature* self, const dash_pkc::ffi::capi::Signature* other);

    typedef struct Signature_verify_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Signature_verify_result;
    Signature_verify_result Signature_verify(const dash_pkc::ffi::capi::Signature* self, diplomat::capi::DiplomatU8View msg, const dash_pkc::ffi::capi::PublicKey* pk, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Signature_aggregate_with_result {union {dash_pkc::ffi::capi::Signature* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Signature_aggregate_with_result;
    Signature_aggregate_with_result Signature_aggregate_with(const dash_pkc::ffi::capi::Signature* self, const dash_pkc::ffi::capi::Signature* other, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Signature_aggregate_result {union {dash_pkc::ffi::capi::Signature* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Signature_aggregate_result;
    Signature_aggregate_result Signature_aggregate(const dash_pkc::ffi::capi::SignatureVec* sigs, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Signature_aggregate_secure_result {union {dash_pkc::ffi::capi::Signature* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Signature_aggregate_secure_result;
    Signature_aggregate_secure_result Signature_aggregate_secure(const dash_pkc::ffi::capi::SignatureVec* sigs, const dash_pkc::ffi::capi::PublicKeyVec* pks, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Signature_verify_secure_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Signature_verify_secure_result;
    Signature_verify_secure_result Signature_verify_secure(const dash_pkc::ffi::capi::Signature* self, const dash_pkc::ffi::capi::PublicKeyVec* pks, diplomat::capi::DiplomatU8View msg, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Signature_verify_aggregated_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Signature_verify_aggregated_result;
    Signature_verify_aggregated_result Signature_verify_aggregated(const dash_pkc::ffi::capi::Signature* self, const dash_pkc::ffi::capi::MessageVec* msgs, const dash_pkc::ffi::capi::PublicKeyVec* pks, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Signature_sub_insecure_result {union {dash_pkc::ffi::capi::Signature* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Signature_sub_insecure_result;
    Signature_sub_insecure_result Signature_sub_insecure(const dash_pkc::ffi::capi::Signature* self, const dash_pkc::ffi::capi::Signature* other);

    typedef struct Signature_recover_result {union {dash_pkc::ffi::capi::Signature* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Signature_recover_result;
    Signature_recover_result Signature_recover(const dash_pkc::ffi::capi::SignatureVec* sigs, const dash_pkc::ffi::capi::IdVec* ids, dash_pkc::ffi::capi::Scheme scheme);

    void Signature_destroy(Signature* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> dash_pkc::ffi::Signature::from_bytes(diplomat::span<const uint8_t> bytes, dash_pkc::ffi::Scheme scheme) {
    auto result = dash_pkc::ffi::capi::Signature_from_bytes({bytes.data(), bytes.size()},
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::Signature>>(std::unique_ptr<dash_pkc::ffi::Signature>(dash_pkc::ffi::Signature::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::Signature::to_bytes(diplomat::span<uint8_t> out, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Signature_to_bytes(this->AsFFI(),
        {out.data(), out.size()},
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline dash_pkc::ffi::Scheme dash_pkc::ffi::Signature::scheme() const {
    auto result = dash_pkc::ffi::capi::Signature_scheme(this->AsFFI());
    return dash_pkc::ffi::Scheme::FromFFI(result);
}

inline std::unique_ptr<dash_pkc::ffi::Signature> dash_pkc::ffi::Signature::clone() const {
    auto result = dash_pkc::ffi::capi::Signature_boxed_clone(this->AsFFI());
    return std::unique_ptr<dash_pkc::ffi::Signature>(dash_pkc::ffi::Signature::FromFFI(result));
}

inline bool dash_pkc::ffi::Signature::eq(const dash_pkc::ffi::Signature& other) const {
    auto result = dash_pkc::ffi::capi::Signature_eq(this->AsFFI(),
        other.AsFFI());
    return result;
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::Signature::verify(diplomat::span<const uint8_t> msg, const dash_pkc::ffi::PublicKey& pk, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Signature_verify(this->AsFFI(),
        {msg.data(), msg.size()},
        pk.AsFFI(),
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> dash_pkc::ffi::Signature::aggregate_with(const dash_pkc::ffi::Signature& other, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Signature_aggregate_with(this->AsFFI(),
        other.AsFFI(),
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::Signature>>(std::unique_ptr<dash_pkc::ffi::Signature>(dash_pkc::ffi::Signature::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> dash_pkc::ffi::Signature::aggregate(const dash_pkc::ffi::SignatureVec& sigs, dash_pkc::ffi::Scheme scheme) {
    auto result = dash_pkc::ffi::capi::Signature_aggregate(sigs.AsFFI(),
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::Signature>>(std::unique_ptr<dash_pkc::ffi::Signature>(dash_pkc::ffi::Signature::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> dash_pkc::ffi::Signature::aggregate_secure(const dash_pkc::ffi::SignatureVec& sigs, const dash_pkc::ffi::PublicKeyVec& pks, dash_pkc::ffi::Scheme scheme) {
    auto result = dash_pkc::ffi::capi::Signature_aggregate_secure(sigs.AsFFI(),
        pks.AsFFI(),
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::Signature>>(std::unique_ptr<dash_pkc::ffi::Signature>(dash_pkc::ffi::Signature::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::Signature::verify_secure(const dash_pkc::ffi::PublicKeyVec& pks, diplomat::span<const uint8_t> msg, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Signature_verify_secure(this->AsFFI(),
        pks.AsFFI(),
        {msg.data(), msg.size()},
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::Signature::verify_aggregated(const dash_pkc::ffi::MessageVec& msgs, const dash_pkc::ffi::PublicKeyVec& pks, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Signature_verify_aggregated(this->AsFFI(),
        msgs.AsFFI(),
        pks.AsFFI(),
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> dash_pkc::ffi::Signature::sub_insecure(const dash_pkc::ffi::Signature& other) const {
    auto result = dash_pkc::ffi::capi::Signature_sub_insecure(this->AsFFI(),
        other.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::Signature>>(std::unique_ptr<dash_pkc::ffi::Signature>(dash_pkc::ffi::Signature::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> dash_pkc::ffi::Signature::recover(const dash_pkc::ffi::SignatureVec& sigs, const dash_pkc::ffi::IdVec& ids, dash_pkc::ffi::Scheme scheme) {
    auto result = dash_pkc::ffi::capi::Signature_recover(sigs.AsFFI(),
        ids.AsFFI(),
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::Signature>>(std::unique_ptr<dash_pkc::ffi::Signature>(dash_pkc::ffi::Signature::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline const dash_pkc::ffi::capi::Signature* dash_pkc::ffi::Signature::AsFFI() const {
    return reinterpret_cast<const dash_pkc::ffi::capi::Signature*>(this);
}

inline dash_pkc::ffi::capi::Signature* dash_pkc::ffi::Signature::AsFFI() {
    return reinterpret_cast<dash_pkc::ffi::capi::Signature*>(this);
}

inline const dash_pkc::ffi::Signature* dash_pkc::ffi::Signature::FromFFI(const dash_pkc::ffi::capi::Signature* ptr) {
    return reinterpret_cast<const dash_pkc::ffi::Signature*>(ptr);
}

inline dash_pkc::ffi::Signature* dash_pkc::ffi::Signature::FromFFI(dash_pkc::ffi::capi::Signature* ptr) {
    return reinterpret_cast<dash_pkc::ffi::Signature*>(ptr);
}

inline void dash_pkc::ffi::Signature::operator delete(void* ptr) {
    dash_pkc::ffi::capi::Signature_destroy(reinterpret_cast<dash_pkc::ffi::capi::Signature*>(ptr));
}


#endif // dash_pkc_ffi_Signature_HPP
