#ifndef dash_pkc_ffi_SignatureVec_HPP
#define dash_pkc_ffi_SignatureVec_HPP

#include "SignatureVec.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "Signature.hpp"
#include "../../diplomat_runtime.hpp"


namespace dash_pkc::ffi {
namespace capi {
    extern "C" {

    dash_pkc::ffi::capi::SignatureVec* SignatureVec_new(void);

    void SignatureVec_push(dash_pkc::ffi::capi::SignatureVec* self, const dash_pkc::ffi::capi::Signature* sig);

    size_t SignatureVec_len(const dash_pkc::ffi::capi::SignatureVec* self);

    void SignatureVec_destroy(SignatureVec* self);

    } // extern "C"
} // namespace capi
} // namespace

inline std::unique_ptr<dash_pkc::ffi::SignatureVec> dash_pkc::ffi::SignatureVec::new_() {
    auto result = dash_pkc::ffi::capi::SignatureVec_new();
    return std::unique_ptr<dash_pkc::ffi::SignatureVec>(dash_pkc::ffi::SignatureVec::FromFFI(result));
}

inline void dash_pkc::ffi::SignatureVec::push(const dash_pkc::ffi::Signature& sig) {
    dash_pkc::ffi::capi::SignatureVec_push(this->AsFFI(),
        sig.AsFFI());
}

inline size_t dash_pkc::ffi::SignatureVec::len() const {
    auto result = dash_pkc::ffi::capi::SignatureVec_len(this->AsFFI());
    return result;
}

inline const dash_pkc::ffi::capi::SignatureVec* dash_pkc::ffi::SignatureVec::AsFFI() const {
    return reinterpret_cast<const dash_pkc::ffi::capi::SignatureVec*>(this);
}

inline dash_pkc::ffi::capi::SignatureVec* dash_pkc::ffi::SignatureVec::AsFFI() {
    return reinterpret_cast<dash_pkc::ffi::capi::SignatureVec*>(this);
}

inline const dash_pkc::ffi::SignatureVec* dash_pkc::ffi::SignatureVec::FromFFI(const dash_pkc::ffi::capi::SignatureVec* ptr) {
    return reinterpret_cast<const dash_pkc::ffi::SignatureVec*>(ptr);
}

inline dash_pkc::ffi::SignatureVec* dash_pkc::ffi::SignatureVec::FromFFI(dash_pkc::ffi::capi::SignatureVec* ptr) {
    return reinterpret_cast<dash_pkc::ffi::SignatureVec*>(ptr);
}

inline void dash_pkc::ffi::SignatureVec::operator delete(void* ptr) {
    dash_pkc::ffi::capi::SignatureVec_destroy(reinterpret_cast<dash_pkc::ffi::capi::SignatureVec*>(ptr));
}


#endif // dash_pkc_ffi_SignatureVec_HPP
