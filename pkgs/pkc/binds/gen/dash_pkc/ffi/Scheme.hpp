#ifndef dash_pkc_ffi_Scheme_HPP
#define dash_pkc_ffi_Scheme_HPP

#include "Scheme.d.hpp"

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

} // namespace capi
} // namespace

inline dash_pkc::ffi::capi::Scheme dash_pkc::ffi::Scheme::AsFFI() const {
    return static_cast<dash_pkc::ffi::capi::Scheme>(value);
}

inline dash_pkc::ffi::Scheme dash_pkc::ffi::Scheme::FromFFI(dash_pkc::ffi::capi::Scheme c_enum) {
    switch (c_enum) {
        case dash_pkc::ffi::capi::Scheme_Legacy:
        case dash_pkc::ffi::capi::Scheme_Basic:
            return static_cast<dash_pkc::ffi::Scheme::Value>(c_enum);
        default:
            std::abort();
    }
}
#endif // dash_pkc_ffi_Scheme_HPP
