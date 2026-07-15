#ifndef dash_pkc_ffi_MessageVec_HPP
#define dash_pkc_ffi_MessageVec_HPP

#include "MessageVec.d.hpp"

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
namespace capi {
    extern "C" {

    dash_pkc::ffi::capi::MessageVec* MessageVec_new(void);

    void MessageVec_push(dash_pkc::ffi::capi::MessageVec* self, diplomat::capi::DiplomatU8View msg);

    size_t MessageVec_len(const dash_pkc::ffi::capi::MessageVec* self);

    void MessageVec_destroy(MessageVec* self);

    } // extern "C"
} // namespace capi
} // namespace

inline std::unique_ptr<dash_pkc::ffi::MessageVec> dash_pkc::ffi::MessageVec::new_() {
    auto result = dash_pkc::ffi::capi::MessageVec_new();
    return std::unique_ptr<dash_pkc::ffi::MessageVec>(dash_pkc::ffi::MessageVec::FromFFI(result));
}

inline void dash_pkc::ffi::MessageVec::push(diplomat::span<const uint8_t> msg) {
    dash_pkc::ffi::capi::MessageVec_push(this->AsFFI(),
        {msg.data(), msg.size()});
}

inline size_t dash_pkc::ffi::MessageVec::len() const {
    auto result = dash_pkc::ffi::capi::MessageVec_len(this->AsFFI());
    return result;
}

inline const dash_pkc::ffi::capi::MessageVec* dash_pkc::ffi::MessageVec::AsFFI() const {
    return reinterpret_cast<const dash_pkc::ffi::capi::MessageVec*>(this);
}

inline dash_pkc::ffi::capi::MessageVec* dash_pkc::ffi::MessageVec::AsFFI() {
    return reinterpret_cast<dash_pkc::ffi::capi::MessageVec*>(this);
}

inline const dash_pkc::ffi::MessageVec* dash_pkc::ffi::MessageVec::FromFFI(const dash_pkc::ffi::capi::MessageVec* ptr) {
    return reinterpret_cast<const dash_pkc::ffi::MessageVec*>(ptr);
}

inline dash_pkc::ffi::MessageVec* dash_pkc::ffi::MessageVec::FromFFI(dash_pkc::ffi::capi::MessageVec* ptr) {
    return reinterpret_cast<dash_pkc::ffi::MessageVec*>(ptr);
}

inline void dash_pkc::ffi::MessageVec::operator delete(void* ptr) {
    dash_pkc::ffi::capi::MessageVec_destroy(reinterpret_cast<dash_pkc::ffi::capi::MessageVec*>(ptr));
}


#endif // dash_pkc_ffi_MessageVec_HPP
