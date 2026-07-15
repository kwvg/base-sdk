#ifndef dash_pkc_ffi_PublicKeyVec_HPP
#define dash_pkc_ffi_PublicKeyVec_HPP

#include "PublicKeyVec.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "PublicKey.hpp"
#include "../../diplomat_runtime.hpp"


namespace dash_pkc::ffi {
namespace capi {
    extern "C" {

    dash_pkc::ffi::capi::PublicKeyVec* PublicKeyVec_new(void);

    void PublicKeyVec_push(dash_pkc::ffi::capi::PublicKeyVec* self, const dash_pkc::ffi::capi::PublicKey* key);

    size_t PublicKeyVec_len(const dash_pkc::ffi::capi::PublicKeyVec* self);

    void PublicKeyVec_destroy(PublicKeyVec* self);

    } // extern "C"
} // namespace capi
} // namespace

inline std::unique_ptr<dash_pkc::ffi::PublicKeyVec> dash_pkc::ffi::PublicKeyVec::new_() {
    auto result = dash_pkc::ffi::capi::PublicKeyVec_new();
    return std::unique_ptr<dash_pkc::ffi::PublicKeyVec>(dash_pkc::ffi::PublicKeyVec::FromFFI(result));
}

inline void dash_pkc::ffi::PublicKeyVec::push(const dash_pkc::ffi::PublicKey& key) {
    dash_pkc::ffi::capi::PublicKeyVec_push(this->AsFFI(),
        key.AsFFI());
}

inline size_t dash_pkc::ffi::PublicKeyVec::len() const {
    auto result = dash_pkc::ffi::capi::PublicKeyVec_len(this->AsFFI());
    return result;
}

inline const dash_pkc::ffi::capi::PublicKeyVec* dash_pkc::ffi::PublicKeyVec::AsFFI() const {
    return reinterpret_cast<const dash_pkc::ffi::capi::PublicKeyVec*>(this);
}

inline dash_pkc::ffi::capi::PublicKeyVec* dash_pkc::ffi::PublicKeyVec::AsFFI() {
    return reinterpret_cast<dash_pkc::ffi::capi::PublicKeyVec*>(this);
}

inline const dash_pkc::ffi::PublicKeyVec* dash_pkc::ffi::PublicKeyVec::FromFFI(const dash_pkc::ffi::capi::PublicKeyVec* ptr) {
    return reinterpret_cast<const dash_pkc::ffi::PublicKeyVec*>(ptr);
}

inline dash_pkc::ffi::PublicKeyVec* dash_pkc::ffi::PublicKeyVec::FromFFI(dash_pkc::ffi::capi::PublicKeyVec* ptr) {
    return reinterpret_cast<dash_pkc::ffi::PublicKeyVec*>(ptr);
}

inline void dash_pkc::ffi::PublicKeyVec::operator delete(void* ptr) {
    dash_pkc::ffi::capi::PublicKeyVec_destroy(reinterpret_cast<dash_pkc::ffi::capi::PublicKeyVec*>(ptr));
}


#endif // dash_pkc_ffi_PublicKeyVec_HPP
