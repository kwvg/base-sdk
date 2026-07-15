#ifndef dash_pkc_ffi_SecretKeyVec_HPP
#define dash_pkc_ffi_SecretKeyVec_HPP

#include "SecretKeyVec.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "SecretKey.hpp"
#include "../../diplomat_runtime.hpp"


namespace dash_pkc::ffi {
namespace capi {
    extern "C" {

    dash_pkc::ffi::capi::SecretKeyVec* SecretKeyVec_new(void);

    void SecretKeyVec_push(dash_pkc::ffi::capi::SecretKeyVec* self, const dash_pkc::ffi::capi::SecretKey* key);

    size_t SecretKeyVec_len(const dash_pkc::ffi::capi::SecretKeyVec* self);

    void SecretKeyVec_destroy(SecretKeyVec* self);

    } // extern "C"
} // namespace capi
} // namespace

inline std::unique_ptr<dash_pkc::ffi::SecretKeyVec> dash_pkc::ffi::SecretKeyVec::new_() {
    auto result = dash_pkc::ffi::capi::SecretKeyVec_new();
    return std::unique_ptr<dash_pkc::ffi::SecretKeyVec>(dash_pkc::ffi::SecretKeyVec::FromFFI(result));
}

inline void dash_pkc::ffi::SecretKeyVec::push(const dash_pkc::ffi::SecretKey& key) {
    dash_pkc::ffi::capi::SecretKeyVec_push(this->AsFFI(),
        key.AsFFI());
}

inline size_t dash_pkc::ffi::SecretKeyVec::len() const {
    auto result = dash_pkc::ffi::capi::SecretKeyVec_len(this->AsFFI());
    return result;
}

inline const dash_pkc::ffi::capi::SecretKeyVec* dash_pkc::ffi::SecretKeyVec::AsFFI() const {
    return reinterpret_cast<const dash_pkc::ffi::capi::SecretKeyVec*>(this);
}

inline dash_pkc::ffi::capi::SecretKeyVec* dash_pkc::ffi::SecretKeyVec::AsFFI() {
    return reinterpret_cast<dash_pkc::ffi::capi::SecretKeyVec*>(this);
}

inline const dash_pkc::ffi::SecretKeyVec* dash_pkc::ffi::SecretKeyVec::FromFFI(const dash_pkc::ffi::capi::SecretKeyVec* ptr) {
    return reinterpret_cast<const dash_pkc::ffi::SecretKeyVec*>(ptr);
}

inline dash_pkc::ffi::SecretKeyVec* dash_pkc::ffi::SecretKeyVec::FromFFI(dash_pkc::ffi::capi::SecretKeyVec* ptr) {
    return reinterpret_cast<dash_pkc::ffi::SecretKeyVec*>(ptr);
}

inline void dash_pkc::ffi::SecretKeyVec::operator delete(void* ptr) {
    dash_pkc::ffi::capi::SecretKeyVec_destroy(reinterpret_cast<dash_pkc::ffi::capi::SecretKeyVec*>(ptr));
}


#endif // dash_pkc_ffi_SecretKeyVec_HPP
