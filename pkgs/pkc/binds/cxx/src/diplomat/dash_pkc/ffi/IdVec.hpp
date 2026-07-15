#ifndef dash_pkc_ffi_IdVec_HPP
#define dash_pkc_ffi_IdVec_HPP

#include "IdVec.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "PkcError.hpp"
#include "../../diplomat_runtime.hpp"


namespace dash_pkc::ffi {
namespace capi {
    extern "C" {

    dash_pkc::ffi::capi::IdVec* IdVec_new(void);

    typedef struct IdVec_push_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} IdVec_push_result;
    IdVec_push_result IdVec_push(dash_pkc::ffi::capi::IdVec* self, diplomat::capi::DiplomatU8View id);

    size_t IdVec_len(const dash_pkc::ffi::capi::IdVec* self);

    void IdVec_destroy(IdVec* self);

    } // extern "C"
} // namespace capi
} // namespace

inline std::unique_ptr<dash_pkc::ffi::IdVec> dash_pkc::ffi::IdVec::new_() {
    auto result = dash_pkc::ffi::capi::IdVec_new();
    return std::unique_ptr<dash_pkc::ffi::IdVec>(dash_pkc::ffi::IdVec::FromFFI(result));
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::IdVec::push(diplomat::span<const uint8_t> id) {
    auto result = dash_pkc::ffi::capi::IdVec_push(this->AsFFI(),
        {id.data(), id.size()});
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline size_t dash_pkc::ffi::IdVec::len() const {
    auto result = dash_pkc::ffi::capi::IdVec_len(this->AsFFI());
    return result;
}

inline const dash_pkc::ffi::capi::IdVec* dash_pkc::ffi::IdVec::AsFFI() const {
    return reinterpret_cast<const dash_pkc::ffi::capi::IdVec*>(this);
}

inline dash_pkc::ffi::capi::IdVec* dash_pkc::ffi::IdVec::AsFFI() {
    return reinterpret_cast<dash_pkc::ffi::capi::IdVec*>(this);
}

inline const dash_pkc::ffi::IdVec* dash_pkc::ffi::IdVec::FromFFI(const dash_pkc::ffi::capi::IdVec* ptr) {
    return reinterpret_cast<const dash_pkc::ffi::IdVec*>(ptr);
}

inline dash_pkc::ffi::IdVec* dash_pkc::ffi::IdVec::FromFFI(dash_pkc::ffi::capi::IdVec* ptr) {
    return reinterpret_cast<dash_pkc::ffi::IdVec*>(ptr);
}

inline void dash_pkc::ffi::IdVec::operator delete(void* ptr) {
    dash_pkc::ffi::capi::IdVec_destroy(reinterpret_cast<dash_pkc::ffi::capi::IdVec*>(ptr));
}


#endif // dash_pkc_ffi_IdVec_HPP
