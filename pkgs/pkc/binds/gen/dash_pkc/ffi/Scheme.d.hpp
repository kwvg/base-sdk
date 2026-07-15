#ifndef dash_pkc_ffi_Scheme_D_HPP
#define dash_pkc_ffi_Scheme_D_HPP

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
    enum Scheme {
      Scheme_Legacy = 0,
      Scheme_Basic = 1,
    };

    typedef struct Scheme_option {union { Scheme ok; }; bool is_ok; } Scheme_option;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * Serialization and signing scheme: `Legacy` is Dash's
 * pre-basic-scheme (Chia) format, `Basic` the IETF format.
 */
class Scheme {
public:
    enum Value {
        Legacy = 0,
        Basic = 1,
    };

    Scheme(): value(Value::Legacy) {}

    // Implicit conversions between enum and ::Value
    constexpr Scheme(Value v) : value(v) {}
    constexpr operator Value() const { return value; }
    // Prevent usage as boolean value
    explicit operator bool() const = delete;

    inline dash_pkc::ffi::capi::Scheme AsFFI() const;
    inline static dash_pkc::ffi::Scheme FromFFI(dash_pkc::ffi::capi::Scheme c_enum);
private:
    Value value;
};

} // namespace
#endif // dash_pkc_ffi_Scheme_D_HPP
