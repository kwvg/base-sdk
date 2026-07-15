#ifndef dash_pkc_ffi_Session_HPP
#define dash_pkc_ffi_Session_HPP

#include "Session.d.hpp"

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
#include "Signature.hpp"
#include "SignatureVec.hpp"
#include "../../diplomat_runtime.hpp"


namespace dash_pkc::ffi {
namespace capi {
    extern "C" {

    typedef struct Session_create_result {union {dash_pkc::ffi::capi::Session* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Session_create_result;
    Session_create_result Session_create(diplomat::capi::DiplomatU8View entropy);

    typedef struct Session_verify_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Session_verify_result;
    Session_verify_result Session_verify(const dash_pkc::ffi::capi::Session* self, const dash_pkc::ffi::capi::Signature* sig, diplomat::capi::DiplomatU8View msg, const dash_pkc::ffi::capi::PublicKey* pk, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Session_verify_aggregated_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Session_verify_aggregated_result;
    Session_verify_aggregated_result Session_verify_aggregated(const dash_pkc::ffi::capi::Session* self, const dash_pkc::ffi::capi::Signature* sig, const dash_pkc::ffi::capi::MessageVec* msgs, const dash_pkc::ffi::capi::PublicKeyVec* pks, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Session_verify_secure_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Session_verify_secure_result;
    Session_verify_secure_result Session_verify_secure(const dash_pkc::ffi::capi::Session* self, const dash_pkc::ffi::capi::Signature* sig, const dash_pkc::ffi::capi::PublicKeyVec* pks, diplomat::capi::DiplomatU8View msg, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Session_aggregate_secure_result {union {dash_pkc::ffi::capi::Signature* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Session_aggregate_secure_result;
    Session_aggregate_secure_result Session_aggregate_secure(const dash_pkc::ffi::capi::Session* self, const dash_pkc::ffi::capi::SignatureVec* sigs, const dash_pkc::ffi::capi::PublicKeyVec* pks, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Session_parse_public_key_result {union {dash_pkc::ffi::capi::PublicKey* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Session_parse_public_key_result;
    Session_parse_public_key_result Session_parse_public_key(const dash_pkc::ffi::capi::Session* self, diplomat::capi::DiplomatU8View bytes, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Session_parse_signature_result {union {dash_pkc::ffi::capi::Signature* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Session_parse_signature_result;
    Session_parse_signature_result Session_parse_signature(const dash_pkc::ffi::capi::Session* self, diplomat::capi::DiplomatU8View bytes, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Session_public_key_share_result {union {dash_pkc::ffi::capi::PublicKey* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Session_public_key_share_result;
    Session_public_key_share_result Session_public_key_share(const dash_pkc::ffi::capi::Session* self, const dash_pkc::ffi::capi::PublicKeyVec* masters, diplomat::capi::DiplomatU8View id, dash_pkc::ffi::capi::Scheme scheme);

    typedef struct Session_recover_signature_result {union {dash_pkc::ffi::capi::Signature* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} Session_recover_signature_result;
    Session_recover_signature_result Session_recover_signature(const dash_pkc::ffi::capi::Session* self, const dash_pkc::ffi::capi::SignatureVec* sigs, const dash_pkc::ffi::capi::IdVec* ids, dash_pkc::ffi::capi::Scheme scheme);

    void Session_destroy(Session* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Session>, dash_pkc::ffi::PkcError> dash_pkc::ffi::Session::create(diplomat::span<const uint8_t> entropy) {
    auto result = dash_pkc::ffi::capi::Session_create({entropy.data(), entropy.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::Session>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::Session>>(std::unique_ptr<dash_pkc::ffi::Session>(dash_pkc::ffi::Session::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::Session>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::Session::verify(const dash_pkc::ffi::Signature& sig, diplomat::span<const uint8_t> msg, const dash_pkc::ffi::PublicKey& pk, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Session_verify(this->AsFFI(),
        sig.AsFFI(),
        {msg.data(), msg.size()},
        pk.AsFFI(),
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::Session::verify_aggregated(const dash_pkc::ffi::Signature& sig, const dash_pkc::ffi::MessageVec& msgs, const dash_pkc::ffi::PublicKeyVec& pks, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Session_verify_aggregated(this->AsFFI(),
        sig.AsFFI(),
        msgs.AsFFI(),
        pks.AsFFI(),
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::Session::verify_secure(const dash_pkc::ffi::Signature& sig, const dash_pkc::ffi::PublicKeyVec& pks, diplomat::span<const uint8_t> msg, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Session_verify_secure(this->AsFFI(),
        sig.AsFFI(),
        pks.AsFFI(),
        {msg.data(), msg.size()},
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> dash_pkc::ffi::Session::aggregate_secure(const dash_pkc::ffi::SignatureVec& sigs, const dash_pkc::ffi::PublicKeyVec& pks, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Session_aggregate_secure(this->AsFFI(),
        sigs.AsFFI(),
        pks.AsFFI(),
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::Signature>>(std::unique_ptr<dash_pkc::ffi::Signature>(dash_pkc::ffi::Signature::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> dash_pkc::ffi::Session::parse_public_key(diplomat::span<const uint8_t> bytes, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Session_parse_public_key(this->AsFFI(),
        {bytes.data(), bytes.size()},
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::PublicKey>>(std::unique_ptr<dash_pkc::ffi::PublicKey>(dash_pkc::ffi::PublicKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> dash_pkc::ffi::Session::parse_signature(diplomat::span<const uint8_t> bytes, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Session_parse_signature(this->AsFFI(),
        {bytes.data(), bytes.size()},
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::Signature>>(std::unique_ptr<dash_pkc::ffi::Signature>(dash_pkc::ffi::Signature::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError> dash_pkc::ffi::Session::public_key_share(const dash_pkc::ffi::PublicKeyVec& masters, diplomat::span<const uint8_t> id, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Session_public_key_share(this->AsFFI(),
        masters.AsFFI(),
        {id.data(), id.size()},
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::PublicKey>>(std::unique_ptr<dash_pkc::ffi::PublicKey>(dash_pkc::ffi::PublicKey::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::PublicKey>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError> dash_pkc::ffi::Session::recover_signature(const dash_pkc::ffi::SignatureVec& sigs, const dash_pkc::ffi::IdVec& ids, dash_pkc::ffi::Scheme scheme) const {
    auto result = dash_pkc::ffi::capi::Session_recover_signature(this->AsFFI(),
        sigs.AsFFI(),
        ids.AsFFI(),
        scheme.AsFFI());
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::Signature>>(std::unique_ptr<dash_pkc::ffi::Signature>(dash_pkc::ffi::Signature::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::Signature>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline const dash_pkc::ffi::capi::Session* dash_pkc::ffi::Session::AsFFI() const {
    return reinterpret_cast<const dash_pkc::ffi::capi::Session*>(this);
}

inline dash_pkc::ffi::capi::Session* dash_pkc::ffi::Session::AsFFI() {
    return reinterpret_cast<dash_pkc::ffi::capi::Session*>(this);
}

inline const dash_pkc::ffi::Session* dash_pkc::ffi::Session::FromFFI(const dash_pkc::ffi::capi::Session* ptr) {
    return reinterpret_cast<const dash_pkc::ffi::Session*>(ptr);
}

inline dash_pkc::ffi::Session* dash_pkc::ffi::Session::FromFFI(dash_pkc::ffi::capi::Session* ptr) {
    return reinterpret_cast<dash_pkc::ffi::Session*>(ptr);
}

inline void dash_pkc::ffi::Session::operator delete(void* ptr) {
    dash_pkc::ffi::capi::Session_destroy(reinterpret_cast<dash_pkc::ffi::capi::Session*>(ptr));
}


#endif // dash_pkc_ffi_Session_HPP
