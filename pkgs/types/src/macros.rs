//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared macros definitions.

/// Maps enum variants to integer constants and display strings.
///
/// Generates the enum definition, integer mapping (via `NumCodec` or inherent
/// `const fn`), and `impl Display` from a single table.
///
/// # Syntax
///
/// Each variant uses one of two forms:
///
/// - `Variant = VALUE` -- display string is `stringify!(Variant)`
/// - `Variant = VALUE => "label"` -- display string is `"label"`
///
/// All variants within one invocation must use the same form.
///
/// ## Infallible
///
/// Generates the enum with a catch-all variant, `impl NumCodec<T>`, and `impl
/// Display`. The catch-all displays as `unknown({v})`.
///
/// ```ignore
/// enum_map! {
///   #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
///   pub enum NIPurpose, u8, Unknown {
///     /// Core P2P port.
///     CoreP2p = 0 => "core_p2p",
///     /// Platform P2P port.
///     PlatformP2p = 1 => "platform_p2p",
///   }
/// }
/// ```
///
/// ## Fallible
///
/// Generates the enum (closed), inherent `const fn from_base` / `to_base`
/// methods, and `impl Display`.
///
/// ```ignore
/// enum_map! {
///   #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
///   pub enum Sec1Byte, u8 {
///     /// Compressed, even Y coordinate.
///     CompEven = 0x02,
///     /// Compressed, odd Y coordinate.
///     CompOdd  = 0x03,
///   }
/// }
/// ```
#[macro_export]
macro_rules! enum_map {
  // Infallible + manual display strings.
  (
    $(#[$enum_attr:meta])*
    $vis:vis enum $enum:ident, $base:ty, $catch_all:ident {
      $(
        $(#[$var_attr:meta])*
        $variant:ident = $value:expr => $display:expr
      ),+ $(,)?
    }
  ) => {
    $crate::enum_map!(@enum $(#[$enum_attr])* $vis $enum, $base, $catch_all {
      $($(#[$var_attr])* $variant,)+
    });
    $crate::enum_map!(@infallible $enum, $base, $catch_all { $($variant = $value),+ });
    $crate::enum_map!(@display_catch_all $enum, $catch_all { $($variant = $display),+ });
  };

  // Infallible + auto-stringize.
  (
    $(#[$enum_attr:meta])*
    $vis:vis enum $enum:ident, $base:ty, $catch_all:ident {
      $(
        $(#[$var_attr:meta])*
        $variant:ident = $value:expr
      ),+ $(,)?
    }
  ) => {
    $crate::enum_map!(@enum $(#[$enum_attr])* $vis $enum, $base, $catch_all {
      $($(#[$var_attr])* $variant,)+
    });
    $crate::enum_map!(@infallible $enum, $base, $catch_all { $($variant = $value),+ });
    $crate::enum_map!(@display_catch_all $enum, $catch_all { $($variant = stringify!($variant)),+ });
  };

  // Fallible + manual display strings.
  (
    $(#[$enum_attr:meta])*
    $vis:vis enum $enum:ident, $base:ty {
      $(
        $(#[$var_attr:meta])*
        $variant:ident = $value:expr => $display:expr
      ),+ $(,)?
    }
  ) => {
    $crate::enum_map!(@enum_closed $(#[$enum_attr])* $vis $enum {
      $($(#[$var_attr])* $variant,)+
    });
    $crate::enum_map!(@fallible $enum, $base { $($variant = $value),+ });
    $crate::enum_map!(@display $enum { $($variant = $display),+ });
  };

  // Fallible + auto-stringize.
  (
    $(#[$enum_attr:meta])*
    $vis:vis enum $enum:ident, $base:ty {
      $(
        $(#[$var_attr:meta])*
        $variant:ident = $value:expr
      ),+ $(,)?
    }
  ) => {
    $crate::enum_map!(@enum_closed $(#[$enum_attr])* $vis $enum {
      $($(#[$var_attr])* $variant,)+
    });
    $crate::enum_map!(@fallible $enum, $base { $($variant = $value),+ });
    $crate::enum_map!(@display $enum { $($variant = stringify!($variant)),+ });
  };

  (@enum $(#[$enum_attr:meta])* $vis:vis $enum:ident, $base:ty, $catch_all:ident {
    $($(#[$var_attr:meta])* $variant:ident,)+
  }) => {
    $(#[$enum_attr])*
    $vis enum $enum {
      $(
        $(#[$var_attr])*
        $variant,
      )+
      /// Unrecognized value.
      $catch_all($base),
    }
  };

  (@enum_closed $(#[$enum_attr:meta])* $vis:vis $enum:ident {
    $($(#[$var_attr:meta])* $variant:ident,)+
  }) => {
    $(#[$enum_attr])*
    $vis enum $enum {
      $(
        $(#[$var_attr])*
        $variant,
      )+
    }
  };

  (@infallible $enum:ident, $base:ty, $catch_all:ident {
    $($variant:ident = $value:expr),+
  }) => {
    impl $crate::codec::NumCodec<$base> for $enum {
      fn from_base(val: $base) -> Self {
        match val {
          $($value => Self::$variant,)+
          other => Self::$catch_all(other),
        }
      }

      fn to_base(&self) -> $base {
        match self {
          $(Self::$variant => $value,)+
          Self::$catch_all(v) => *v,
        }
      }
    }

    impl $enum {
      /// Named variants.
      pub const fn variants() -> &'static [Self] {
        &[$(Self::$variant),+]
      }
    }
  };

  (@fallible $enum:ident, $base:ty {
    $($variant:ident = $value:expr),+
  }) => {
    impl $enum {
      /// Constructs from the base integer value.
      pub const fn from_base(v: $base) -> Option<Self> {
        match v {
          $($value => Some(Self::$variant),)+
          _ => None,
        }
      }

      /// Returns the base integer value.
      pub const fn to_base(self) -> $base {
        match self {
          $(Self::$variant => $value,)+
        }
      }

      /// All variants.
      pub const fn variants() -> &'static [Self] {
        &[$(Self::$variant),+]
      }
    }
  };

  (@display_catch_all $enum:ident, $catch_all:ident {
    $($variant:ident = $display:expr),+
  }) => {
    impl core::fmt::Display for $enum {
      fn fmt(
        &self, f: &mut core::fmt::Formatter<'_>,
      ) -> core::fmt::Result {
        match self {
          $(Self::$variant => f.write_str($display),)+
          Self::$catch_all(v) => write!(f, "unknown({v})"),
        }
      }
    }
  };

  (@display $enum:ident {
    $($variant:ident = $display:expr),+
  }) => {
    impl core::fmt::Display for $enum {
      fn fmt(
        &self, f: &mut core::fmt::Formatter<'_>,
      ) -> core::fmt::Result {
        match self {
          $(Self::$variant => f.write_str($display),)+
        }
      }
    }
  };
}

/// Generates `From<T>` + `From<&T>` (or `TryFrom` equivalents). The closure
/// body receives `&$src`; the owned impl delegates.
#[macro_export]
macro_rules! type_cvrt {
  (From<$src:ty> for $dst:ty, |$v:ident| $body:expr) => {
    impl core::convert::From<&$src> for $dst {
      fn from($v: &$src) -> Self {
        $body
      }
    }
    impl core::convert::From<$src> for $dst {
      fn from(v: $src) -> Self {
        Self::from(&v)
      }
    }
  };
  (TryFrom<$src:ty> for $dst:ty, $err:ty, |$v:ident| $body:expr) => {
    impl core::convert::TryFrom<&$src> for $dst {
      type Error = $err;
      fn try_from($v: &$src) -> Result<Self, Self::Error> {
        $body
      }
    }
    impl core::convert::TryFrom<$src> for $dst {
      type Error = $err;
      fn try_from(v: $src) -> Result<Self, Self::Error> {
        Self::try_from(&v)
      }
    }
  };
}

/// Delegates `BaseCodec`, `Hashable`, and `impl_type!` through another type.
#[macro_export]
macro_rules! dlgt_codec {
  ($ops:ty => $bytes:ty, $hash:ty) => {
    impl $crate::codec::BaseCodec for $ops {
      fn decode(data: &mut &[u8]) -> Result<Self, $crate::codec::DecodeError> {
        let inner = <$bytes as $crate::codec::BaseCodec>::decode(data)?;
        Self::try_from(inner).map_err(|_| $crate::codec::DecodeError::InvalidValue {
          expected: ::alloc::vec![],
          actual: 0,
        })
      }

      fn encode(&self, buf: &mut impl $crate::codec::EncodeBuf) {
        <$bytes as core::convert::From<Self>>::from(self.clone()).encode(buf);
      }
    }

    impl $crate::codec::Hashable for $ops {
      type Hash = $hash;

      fn hash(&self) -> $hash {
        $crate::codec::Hashable::hash(&<$bytes as core::convert::From<Self>>::from(self.clone()))
      }
    }

    $crate::impl_type!($ops);
  };
  ($ops:ty => $bytes:ty, $hash:ty, $err:ty) => {
    impl $crate::codec::BaseCodec<$err> for $ops {
      fn decode(data: &mut &[u8]) -> Result<Self, $crate::codec::DecodeError<$err>> {
        let inner = <$bytes as $crate::codec::BaseCodec>::decode(data).map_err(|e| e.lift())?;
        Self::try_from(inner).map_err($crate::codec::DecodeError::DecError)
      }

      fn encode(&self, buf: &mut impl $crate::codec::EncodeBuf) {
        if let Ok(bytes) = <$bytes as core::convert::TryFrom<Self>>::try_from(self.clone()) {
          bytes.encode(buf);
        }
      }
    }

    impl $crate::codec::Hashable for $ops {
      type Hash = $hash;

      fn hash(&self) -> $hash {
        match <$bytes as core::convert::TryFrom<Self>>::try_from(self.clone()) {
          Ok(bytes) => $crate::codec::Hashable::hash(&bytes),
          Err(_) => <$hash as Default>::default(),
        }
      }
    }

    $crate::impl_type!($ops, $crate::MAX_SER_SIZE, $err);
  };
}
