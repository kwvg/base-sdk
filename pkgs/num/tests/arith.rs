//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Arithmetic and hash-arith conversion tests.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_num::{Arith256, Hash256};
use hex_literal::hex;
use rstest::*;

use core::str::FromStr;

fn arith_from_le(bytes: &[u8; 32]) -> Arith256 {
  Arith256::from(Hash256::from_bytes(*bytes))
}

fn arith_from_hex(s: &str) -> Arith256 {
  Arith256::from(Hash256::from_str(s).unwrap())
}

/// Construct Arith256 from big-endian array of four u64 limbs.
fn from_array(a: [u64; 4]) -> Arith256 {
  let hi = (a[0] as u128) << 64 | (a[1] as u128);
  let lo = (a[2] as u128) << 64 | (a[3] as u128);
  let mut bytes = [0u8; 32];
  bytes[..16].copy_from_slice(&lo.to_le_bytes());
  bytes[16..].copy_from_slice(&hi.to_le_bytes());
  Arith256::from_le_bytes(bytes)
}

#[fixture]
fn r1_bytes() -> [u8; 32] {
  hex!("9c524adbcf5611122b29125e5d35d2d22281aab533f00832d556b1f9eae51d7d")
}

#[fixture]
fn r1_hex() -> &'static str {
  "7d1de5eaf9b156d53208f033b5aa8122d2d2355d5e12292b121156cfdb4a529c"
}

#[fixture]
fn r2_bytes() -> [u8; 32] {
  hex!("70321d7c47a56b40267e0ac3a69cb6bf133047a3192dda71491372f0b4ca81d7")
}

#[fixture]
fn r2_hex() -> &'static str {
  "d781cab4f072134971da2d19a3473013bfb69ca6c30a7e26406ba5477c1d3270"
}

#[fixture]
fn one_hash() -> Hash256 {
  Hash256::from_bytes({
    let mut a = [0u8; 32];
    a[0] = 1;
    a
  })
}

#[fixture]
fn r1(r1_bytes: [u8; 32]) -> Arith256 {
  arith_from_le(&r1_bytes)
}

#[fixture]
fn r2(r2_bytes: [u8; 32]) -> Arith256 {
  arith_from_le(&r2_bytes)
}

const R1_LOW64: u64 = 0x121156cfdb4a529c;

mod conversion {
  use super::*;

  #[rstest]
  fn roundtrip_hash_arith_hash(r1_bytes: [u8; 32], r2_bytes: [u8; 32], one_hash: Hash256) {
    for h in [
      Hash256::ZERO,
      one_hash,
      Hash256::from_bytes(r1_bytes),
      Hash256::from_bytes(r2_bytes),
    ] {
      assert_eq!(Hash256::from(Arith256::from(h)), h);
    }
  }

  #[rstest]
  fn hash_to_arith_zero_and_one(one_hash: Hash256) {
    assert_eq!(Arith256::from(Hash256::ZERO), Arith256::ZERO);
    assert_eq!(Arith256::from(one_hash), Arith256::ONE);
  }

  #[rstest]
  fn arith_to_hash_zero_and_one(one_hash: Hash256) {
    assert_eq!(Hash256::from(Arith256::ZERO), Hash256::ZERO);
    assert_eq!(Hash256::from(Arith256::ONE), one_hash);
  }

  #[rstest]
  fn hex_through_arith_matches_hash(r1_bytes: [u8; 32], r2_bytes: [u8; 32]) {
    for bytes in [r1_bytes, r2_bytes] {
      let h = Hash256::from_bytes(bytes);
      let a = Arith256::from(h);
      assert_eq!(format!("{h}"), format!("{a}"));
    }
  }

  #[rstest]
  fn arith_from_hex_equals_from_hash(r1_bytes: [u8; 32], r1_hex: &str, r2_bytes: [u8; 32], r2_hex: &str) {
    assert_eq!(arith_from_le(&r1_bytes), arith_from_hex(r1_hex));
    assert_eq!(arith_from_le(&r2_bytes), arith_from_hex(r2_hex));
  }

  #[rstest]
  fn from_u8() {
    assert_eq!(Arith256::from(0xbe_u8), Arith256::from_u64(0xbe));
  }

  #[rstest]
  fn from_u16() {
    assert_eq!(Arith256::from(0xbeef_u16), Arith256::from_u64(0xbeef));
  }

  #[rstest]
  fn from_u32() {
    assert_eq!(Arith256::from(0xdeadbeef_u32), Arith256::from_u64(0xdeadbeef));
  }

  #[rstest]
  fn from_u64() {
    assert_eq!(
      Arith256::from(0xdead_beef_cafe_babe_u64),
      Arith256::from_u64(0xdead_beef_cafe_babe)
    );
  }

  #[rstest]
  fn from_u128() {
    let v = 0xdead_beef_cafe_babe_0123_4567_89ab_cdef_u128;
    assert_eq!(Arith256::from(v), Arith256::from_u128(v));
  }

  #[rstest]
  fn from_unsigned_0xab() {
    let want = Arith256::from_u64(0xAB);
    assert_eq!(Arith256::from(0xAB_u8), want);
    assert_eq!(Arith256::from(0xAB_u16), want);
    assert_eq!(Arith256::from(0xAB_u32), want);
    assert_eq!(Arith256::from(0xAB_u64), want);
    assert_eq!(Arith256::from(0xAB_u128), want);
  }
}

mod byte_conversion {
  use super::*;

  const BE_BYTES: [u8; 32] = [
    0x1b, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe, 0x2b, 0xed, 0xfe, 0xed, 0xba, 0xad, 0xf0,
    0x0d, 0xde, 0xfa, 0xce, 0xda, 0x11, 0xfe, 0xd2, 0xba, 0xd1, 0xc0, 0xff, 0xe0,
  ];

  const LE_BYTES: [u8; 32] = [
    0xe0, 0xff, 0xc0, 0xd1, 0xba, 0xd2, 0xfe, 0x11, 0xda, 0xce, 0xfa, 0xde, 0x0d, 0xf0, 0xad, 0xba, 0xed, 0xfe, 0xed,
    0x2b, 0xbe, 0xba, 0xaf, 0xde, 0xef, 0xbe, 0xad, 0xde, 0xfe, 0xca, 0xad, 0x1b,
  ];

  fn want() -> Arith256 {
    from_array([
      0x1bad_cafe_dead_beef,
      0xdeaf_babe_2bed_feed,
      0xbaad_f00d_defa_ceda,
      0x11fe_d2ba_d1c0_ffe0,
    ])
  }

  #[rstest]
  fn to_be_bytes() {
    assert_eq!(want().to_be_bytes(), BE_BYTES);
  }

  #[rstest]
  fn from_be_bytes() {
    assert_eq!(Arith256::from_be_bytes(BE_BYTES), want());
  }

  #[rstest]
  fn to_le_bytes() {
    assert_eq!(want().to_le_bytes(), LE_BYTES);
  }

  #[rstest]
  fn from_le_bytes() {
    assert_eq!(Arith256::from_le_bytes(LE_BYTES), want());
  }

  #[rstest]
  fn roundtrip_be() {
    let v = want();
    assert_eq!(Arith256::from_be_bytes(v.to_be_bytes()), v);
  }

  #[rstest]
  fn roundtrip_le() {
    let v = want();
    assert_eq!(Arith256::from_le_bytes(v.to_le_bytes()), v);
  }

  #[rstest]
  fn from_be_array_u64() {
    let v = from_array([
      0x1bad_cafe_dead_beef,
      0xdeaf_babe_2bed_feed,
      0xbaad_f00d_defa_ceda,
      0x11fe_d2ba_d1c0_ffe0,
    ]);
    assert_eq!(v, want());
  }
}

mod add_sub {
  use super::*;

  #[rstest]
  fn self_ops() {
    let two = arith_from_hex("02");
    let mut v = two;

    v *= v;
    assert_eq!(v, arith_from_hex("04"));
    v /= v;
    assert_eq!(v, arith_from_hex("01"));
    v += v;
    assert_eq!(v, arith_from_hex("02"));
    v -= v;
    assert_eq!(v, Arith256::ZERO);
  }

  #[rstest]
  fn r1_plus_r2(r1: Arith256, r2: Arith256) {
    let expected = arith_from_hex("549fb09fea236a1ea3e31d4d58f1b1369288d204211ca751527cfc175767850c");
    assert_eq!(r1 + r2, expected);
  }

  #[rstest]
  fn one_plus_max() {
    assert_eq!(Arith256::ONE + Arith256::MAX, Arith256::ZERO);
    assert_eq!(Arith256::MAX + Arith256::ONE, Arith256::ZERO);
  }

  #[rstest]
  fn known_u64() {
    let a = Arith256::from_u64(0xbedc77e27940a7);
    let b = Arith256::from_u64(0xee8d836fce66fb);
    assert_eq!(a + b, Arith256::from_u64(0xbedc77e27940a7 + 0xee8d836fce66fb));
  }

  /// `(Max >> i) + 1 == Half >> (i - 1)` for all valid i.
  #[rstest]
  fn shifted_max_plus_one() {
    let half = Arith256::ONE << 255u32;
    for i in 1..256u32 {
      assert_eq!((Arith256::MAX >> i) + Arith256::ONE, half >> (i - 1));
    }
  }

  #[rstest]
  fn double_negation(r1: Arith256, r2: Arith256) {
    assert_eq!(r1 - (-r2), r1 + r2);
    assert_eq!(r1 - (-Arith256::ONE), r1 + Arith256::ONE);
    assert_eq!(r1 - Arith256::ONE, r1 + (-Arith256::ONE));
  }

  /// `-(1 << i) == Max << i` for all bit positions.
  #[rstest]
  fn neg_shifted_one() {
    for i in 0..256u32 {
      assert_eq!(-(Arith256::ONE << i), Arith256::MAX << i);
    }
  }

  #[rstest]
  fn wrapping_add_wraps() {
    assert_eq!(Arith256::MAX.wrapping_add(Arith256::ONE), Arith256::ZERO);
    assert_eq!(Arith256::MAX.wrapping_add(Arith256::from(2_u8)), Arith256::ONE);
  }

  #[rstest]
  fn wrapping_sub_wraps() {
    assert_eq!(Arith256::ZERO.wrapping_sub(Arith256::ONE), Arith256::MAX);
    assert_eq!(Arith256::ONE.wrapping_sub(Arith256::from(2_u8)), Arith256::MAX);
  }

  #[rstest]
  fn addition_cross_limb() {
    let x = Arith256::from_u128(u128::MAX);
    let add = x.wrapping_add(Arith256::ONE);
    assert_eq!(add, from_array([0, 1, 0, 0]));

    let add2 = add.wrapping_add(Arith256::ONE);
    assert_eq!(add2, from_array([0, 1, 0, 1]));
  }

  #[rstest]
  fn subtraction_cross_limb() {
    let x = from_array([0, 1, 0, 0]);
    let sub = x.wrapping_sub(Arith256::ONE);
    assert_eq!(sub, Arith256::from_u128(u128::MAX));
  }
}

mod multiply {
  use super::*;

  #[rstest]
  fn r1_squared(r1: Arith256) {
    assert_eq!(
      format!("{}", r1 * r1),
      "62a38c0486f01e45879d7910a7761bf30d5237e9873f9bff3642a732c4d84f10"
    );
  }

  #[rstest]
  fn r1_times_r2(r1: Arith256, r2: Arith256) {
    assert_eq!(
      format!("{}", r1 * r2),
      "de37805e9986996cfba76ff6ba51c008df851987d9dd323f0e5de07760529c40"
    );
    assert_eq!(r1 * r2, r2 * r1);
  }

  #[rstest]
  fn r2_squared(r2: Arith256) {
    assert_eq!(
      format!("{}", r2 * r2),
      "ac8c010096767d3cae5005dec28bb2b45a1d85ab7996ccd3e102a650f74ff100"
    );
  }

  #[rstest]
  fn identity_and_negation(r1: Arith256, r2: Arith256) {
    assert_eq!(r1 * Arith256::ZERO, Arith256::ZERO);
    assert_eq!(r1 * Arith256::ONE, r1);
    assert_eq!(r1 * Arith256::MAX, -r1);
    assert_eq!(r2 * Arith256::ZERO, Arith256::ZERO);
    assert_eq!(r2 * Arith256::ONE, r2);
    assert_eq!(r2 * Arith256::MAX, -r2);
    assert_eq!(Arith256::MAX * Arith256::MAX, Arith256::ONE);
  }

  #[rstest]
  fn u32_known_results(r1: Arith256, r2: Arith256) {
    #[expect(clippy::erasing_op, reason = "intentional multiply-by-zero test")]
    {
      assert_eq!(r1 * 0u32, Arith256::ZERO);
    }
    assert_eq!(r1 * 1u32, r1);
    assert_eq!(
      format!("{}", r1 * 3u32),
      "7759b1c0ed14047f961ad09b20ff83687876a0181a367b813634046f91def7d4"
    );
    assert_eq!(
      format!("{}", r2 * 0x87654321u32),
      "23f7816e30c4ae2017257b7a0fa64d60402f5234d46e746b61c960d09a26d070"
    );
  }

  #[rstest]
  fn cross_limb() {
    let a = Arith256::from_u128(1u128 << 64);
    let expected = Arith256::from_le_bytes({
      let mut bytes = [0u8; 32];
      bytes[16] = 1;
      bytes
    });
    assert_eq!(a * a, expected);
  }

  #[rstest]
  fn known_multiplication() {
    let u64_val = Arith256::from(0xDEAD_BEEF_DEAD_BEEF_u64);
    let u128_res = u64_val.wrapping_mul(u64_val);
    assert_eq!(
      u128_res,
      from_array([0, 0, 0xC1B1_CD13_A4D1_3D46, 0x048D_1354_216D_A321])
    );

    let u256_res = u128_res.wrapping_mul(u128_res);
    assert_eq!(
      u256_res,
      from_array([
        0x928D_92B4_D7F5_DF33,
        0x4AFC_FF6F_0375_C608,
        0xF5CF_7F36_18C2_C886,
        0xF4E1_66AA_D40D_0A41,
      ])
    );
  }

  #[rstest]
  fn multiplication_bits_in_each_word() {
    let x = from_array([
      0x0000_0000_0000_0001,
      0x0000_0000_0000_0001,
      0x0000_0000_0000_0001,
      0x0000_0000_0000_0001,
    ]);
    let y = from_array([
      0x0000_0000_0000_0002,
      0x0000_0000_0000_0002,
      0x0000_0000_0000_0002,
      0x0000_0000_0000_0002,
    ]);

    // x = 1 + 2^64 + 2^128 + 2^192, y = 2 + 2^65 + 2^129 + 2^193
    // x*y mod 2^256 = 2 + 2^66 + 3*2^129 + 2^195
    //               = limbs [2, 4, 6, 8] (low to high 64-bit words)
    let got = x.wrapping_mul(y);
    let want = from_array([
      0x0000_0000_0000_0008,
      0x0000_0000_0000_0006,
      0x0000_0000_0000_0004,
      0x0000_0000_0000_0002,
    ]);
    assert_eq!(got, want);
  }
}

mod divide {
  use super::*;

  #[rstest]
  fn known_results(r1: Arith256, r2: Arith256) {
    let d1 = arith_from_hex("0AD7133AC1977FA2B7");
    let d2 = arith_from_hex("0ECD751716");

    assert_eq!(
      format!("{}", r1 / d1),
      "00000000000000000b8ac01106981635d9ed112290f8895545a7654dde28fb3a"
    );
    assert_eq!(
      format!("{}", r1 / d2),
      "000000000873ce8efec5b67150bad3aa8c5fcb70e947586153bf2cec7c37c57a"
    );
    assert_eq!(r1 / Arith256::ONE, r1);
    assert_eq!(r1 / Arith256::MAX, Arith256::ZERO);
    assert_eq!(Arith256::MAX / r1, Arith256::from_u64(2));

    assert_eq!(
      format!("{}", r2 / d1),
      "000000000000000013e1665895a1cc981de6d93670105a6b3ec3b73141b3a3c5"
    );
    assert_eq!(
      format!("{}", r2 / d2),
      "000000000e8f0abe753bb0afe2e9437ee85d280be60882cf0bd1aaf7fa3cc2c4"
    );
    assert_eq!(r2 / Arith256::ONE, r2);
    assert_eq!(r2 / Arith256::MAX, Arith256::ZERO);
    assert_eq!(Arith256::MAX / r2, Arith256::from_u64(1));
  }

  #[rstest]
  fn by_zero_returns_zero() {
    assert_eq!(Arith256::from_u64(42) / Arith256::ZERO, Arith256::ZERO);
  }

  #[rstest]
  fn remainder() {
    let (q, r) = Arith256::from_u64(100).div_rem(Arith256::from_u64(7));
    assert_eq!(q, Arith256::from_u64(14));
    assert_eq!(r, Arith256::from_u64(2));
  }

  #[rstest]
  fn arithmetic_chain() {
    let init = Arith256::from(0xDEAD_BEEF_DEAD_BEEF_u64);
    let copy = init;

    let add = init.wrapping_add(copy);
    assert_eq!(add, from_array([0, 0, 1, 0xBD5B_7DDF_BD5B_7DDE]));

    let shl = add << 88u32;
    assert_eq!(shl, from_array([0, 0x01BD_5B7D, 0xDFBD_5B7D_DE00_0000, 0]));

    let shr = shl >> 40u32;
    assert_eq!(shr, from_array([0, 0, 0x0001_BD5B_7DDF_BD5B, 0x7DDE_0000_0000_0000]));

    let incr = shr.wrapping_inc();
    assert_eq!(incr, from_array([0, 0, 0x0001_BD5B_7DDF_BD5B, 0x7DDE_0000_0000_0001]));

    let sub = incr.wrapping_sub(init);
    assert_eq!(sub, from_array([0, 0, 0x0001_BD5B_7DDF_BD5A, 0x9F30_4110_2152_4112]));

    let (mult, _) = sub.mul_u64(300);
    assert_eq!(mult, from_array([0, 0, 0x0209_E737_8231_E632, 0x8C8C_3EE7_0C64_4118]));

    assert_eq!(Arith256::from(105_u32) / Arith256::from(5_u32), Arith256::from(21_u32));
    let div = mult / Arith256::from(300_u32);
    assert_eq!(div, from_array([0, 0, 0x0001_BD5B_7DDF_BD5A, 0x9F30_4110_2152_4112]));

    // Remainder tests
    assert_eq!(Arith256::from(105_u32) % Arith256::from(5_u32), Arith256::ZERO);
    assert_eq!(
      Arith256::from(35498456_u32) % Arith256::from(3435_u32),
      Arith256::from(1166_u32)
    );
    let rem_src = mult
      .wrapping_mul(Arith256::from(39842_u32))
      .wrapping_add(Arith256::from(9054_u32));
    assert_eq!(rem_src % Arith256::from(39842_u32), Arith256::from(9054_u32));
  }
}

mod shifts {
  use super::*;

  fn shift_array_right(from: &[u8; 32], n: u32) -> [u8; 32] {
    let mut to = [0u8; 32];
    let bit = (n % 8) as usize;
    for (t, dst) in to.iter_mut().enumerate() {
      let f = t + (n as usize / 8);
      if f < 32 {
        *dst = from[f] >> bit;
      }
      if f + 1 < 32 && bit != 0 {
        *dst |= from[f + 1] << (8 - bit);
      }
    }
    to
  }

  fn shift_array_left(from: &[u8; 32], n: u32) -> [u8; 32] {
    let mut to = [0u8; 32];
    let bit = (n % 8) as usize;
    for (t, dst) in to.iter_mut().enumerate() {
      if t >= n as usize / 8 {
        let f = t - n as usize / 8;
        *dst = from[f] << bit;
        if t > n as usize / 8 && bit != 0 {
          *dst |= from[f - 1] >> (8 - bit);
        }
      }
    }
    to
  }

  /// Test all 256 shift positions against a byte-array
  /// oracle for One, R1, and Max.
  #[rstest]
  fn exhaustive(r1_bytes: [u8; 32]) {
    let r1 = arith_from_le(&r1_bytes);
    let one_arr = {
      let mut a = [0u8; 32];
      a[0] = 1;
      a
    };
    let max_arr = [0xffu8; 32];
    let half = Arith256::ONE << 255u32;

    for i in 0..256u32 {
      assert_eq!(Arith256::ONE << i, arith_from_le(&shift_array_left(&one_arr, i)));
      assert_eq!(half >> (255 - i), Arith256::ONE << i);
      assert_eq!(r1 << i, arith_from_le(&shift_array_left(&r1_bytes, i)));
      assert_eq!(r1 >> i, arith_from_le(&shift_array_right(&r1_bytes, i)));
      assert_eq!(Arith256::MAX << i, arith_from_le(&shift_array_left(&max_arr, i)));
      assert_eq!(Arith256::MAX >> i, arith_from_le(&shift_array_right(&max_arr, i)));
    }

    assert_eq!(Arith256::ONE << 256u32, Arith256::ZERO);
  }

  #[rstest]
  fn symmetry() {
    let c1 = Arith256::from_u64(0x0123456789abcdef);
    let c2 = c1 << 128u32;
    for i in 0..128u32 {
      assert_eq!(c1 << i, c2 >> (128 - i));
    }
    for i in 128..256u32 {
      assert_eq!(c1 << i, c2 << (i - 128));
    }
  }

  #[rstest]
  fn shift_left_known() {
    let u = Arith256::from(1_u32);
    assert_eq!(u << 0u32, u);
    assert_eq!(u << 1u32, Arith256::from(2_u64));
    assert_eq!(u << 63u32, Arith256::from(0x8000_0000_0000_0000_u64));
    assert_eq!(u << 64u32, from_array([0, 0, 0x0000_0000_0000_0001, 0]));
    assert_eq!(u << 128u32, from_array([0, 1, 0, 0]));
  }

  #[rstest]
  fn shift_right_known() {
    let u = from_array([0, 1, 0, 0]); // 1 << 128
    assert_eq!(u >> 0u32, u);
    assert_eq!(u >> 128u32, Arith256::from(1_u64));
  }

  #[rstest]
  fn extreme_bitshift() {
    let init = Arith256::from(0xDEAD_BEEF_DEAD_BEEF_u64);

    let add = (init << 64u32).wrapping_add(init);
    assert_eq!(add >> 0u32, add);
    assert_eq!(add << 0u32, add);
  }
}

mod bitwise {
  use super::*;

  #[rstest]
  fn against_bytes(r1_bytes: [u8; 32], r2_bytes: [u8; 32]) {
    let r1 = arith_from_le(&r1_bytes);
    let r2 = arith_from_le(&r2_bytes);

    let mut xor = [0u8; 32];
    let mut or = [0u8; 32];
    let mut and = [0u8; 32];
    for i in 0..32 {
      xor[i] = r1_bytes[i] ^ r2_bytes[i];
      or[i] = r1_bytes[i] | r2_bytes[i];
      and[i] = r1_bytes[i] & r2_bytes[i];
    }

    assert_eq!(r1 ^ r2, arith_from_le(&xor));
    assert_eq!(r1 | r2, arith_from_le(&or));
    assert_eq!(r1 & r2, arith_from_le(&and));
  }

  #[rstest]
  fn xor_cancellation(r1: Arith256, r2: Arith256) {
    assert_eq!((r1 ^ r2) ^ r1, r2);
  }

  #[rstest]
  fn not_against_bytes(r1_bytes: [u8; 32]) {
    let r1 = arith_from_le(&r1_bytes);
    let mut not = [0u8; 32];
    for i in 0..32 {
      not[i] = !r1_bytes[i];
    }
    assert_eq!(!r1, arith_from_le(&not));
  }

  #[rstest]
  fn not_identity() {
    assert_eq!(!Arith256::ZERO, Arith256::MAX);
    assert_eq!(!Arith256::MAX, Arith256::ZERO);
  }

  #[rstest]
  fn neg() {
    assert_eq!(-Arith256::ZERO, Arith256::ZERO);
    assert_eq!(-Arith256::ONE, Arith256::MAX);
  }

  #[rstest]
  fn bit_inversion() {
    let v = from_array([0, 1, 0, 0]);
    let want = from_array([
      0xffff_ffff_ffff_ffff,
      0xffff_ffff_ffff_fffe,
      0xffff_ffff_ffff_ffff,
      0xffff_ffff_ffff_ffff,
    ]);
    assert_eq!(!v, want);
  }
}

mod comparison {
  use super::*;

  /// `(1 << i) | R1 >= R1` and related ordering
  /// properties at every bit position.
  #[rstest]
  fn exhaustive(r1: Arith256) {
    for i in 0..256u32 {
      let tmp = Arith256::ONE << i;
      assert!(tmp >= Arith256::ZERO);
      assert!(tmp > Arith256::ZERO);

      let tmp_or = tmp | r1;
      assert!(tmp_or >= r1);
      assert!((tmp_or == r1) != (tmp_or > r1));
    }
  }

  #[rstest]
  fn numeric() {
    let a = Arith256::from_u64(1);
    let b = Arith256::from_u64(2);
    assert!(a < b);
    assert!(b > a);
    assert_eq!(a, a);
  }

  #[rstest]
  fn cross_limb() {
    let lo_max = Arith256::from_u128(u128::MAX);
    let hi_one = Arith256::from_le_bytes({
      let mut b = [0u8; 32];
      b[16] = 1;
      b
    });
    assert!(hi_one > lo_max);
  }

  #[rstest]
  fn comp() {
    let small = from_array([0, 0, 0, 10]);
    let big = from_array([0, 0, 0x0209_E737_8231_E632, 0x8C8C_3EE7_0C64_4118]);
    let bigger = from_array([0, 0, 0x0209_E737_8231_E632, 0x9C8C_3EE7_0C64_4118]);
    let biggest = from_array([1, 0, 0x0209_E737_8231_E632, 0x5C8C_3EE7_0C64_4118]);

    assert!(small < big);
    assert!(big < bigger);
    assert!(bigger < biggest);
    assert!(bigger <= biggest);
    assert!(biggest <= biggest);
    assert!(bigger >= big);
    assert!(bigger >= small);
    assert!(small <= small);
  }
}

mod methods {
  use super::*;

  #[rstest]
  fn low_u64_known(r1: Arith256) {
    assert_eq!(r1.low_u64(), R1_LOW64);
    assert_eq!((Arith256::ONE << 255u32).low_u64(), 0);
    assert_eq!(Arith256::ONE.low_u64(), 1);
  }

  #[rstest]
  fn low_u32_known() {
    assert_eq!(Arith256::from_u64(0xDEAD_BEEF).low_u32(), 0xDEAD_BEEF_u32);
    assert_eq!(Arith256::ZERO.low_u32(), 0);
  }

  #[rstest]
  fn is_one() {
    assert!(Arith256::ONE.is_one());
    assert!(!Arith256::ZERO.is_one());
    assert!(!Arith256::MAX.is_one());
    assert!(!Arith256::from_u64(2).is_one());
  }

  #[rstest]
  fn is_max() {
    assert!(Arith256::MAX.is_max());
    assert!(!Arith256::ZERO.is_max());
    assert!(!Arith256::ONE.is_max());
    assert!(!Arith256::from_u128(u128::MAX).is_max());
    // Construct MAX from parts
    let u = Arith256::from_u128(u128::MAX);
    assert!(((u << 128u32) + u).is_max());
  }

  #[rstest]
  fn saturating_to_u128() {
    assert_eq!(Arith256::ZERO.saturating_to_u128(), 0);
    assert_eq!(Arith256::ONE.saturating_to_u128(), 1);
    assert_eq!(Arith256::from_u128(u128::MAX).saturating_to_u128(), u128::MAX);
    assert_eq!(Arith256::MAX.saturating_to_u128(), u128::MAX);
    assert_eq!((Arith256::ONE << 128u32).saturating_to_u128(), u128::MAX);
  }

  #[rstest]
  fn to_f64_powers_of_two() {
    for i in 0..255u32 {
      let val = (Arith256::ONE << i).to_f64();
      let expected = (2.0_f64).powi(i as i32);
      assert_eq!(val, expected, "mismatch at 1 << {i}");
    }
    assert_eq!(Arith256::ZERO.to_f64(), 0.0);
  }

  /// `(R1 >> (256 - i)).to_f64()` is approximately
  /// `R1_DOUBLE * 2^i` for i in (53..256].
  #[rstest]
  fn to_f64_r1_shifted(r1: Arith256) {
    let r1_double = 0.488_737_459_055_930_9_f64;
    for i in (54..=256).rev() {
      let actual = (r1 >> (256 - i as u32)).to_f64();
      let expected = r1_double * (2.0_f64).powi(i);
      let rel_err = ((actual - expected) / actual).abs();
      assert!(rel_err < 1e-12, "to_f64 drift at i={i}: {actual} vs {expected}");
    }
  }

  /// For small shifts the result fits in u64, so to_f64
  /// must be exact.
  #[rstest]
  fn to_f64_exact_small(r1: Arith256) {
    let r1_top64 = (r1 >> 192u32).low_u64();
    for i in 1..=53u32 {
      let actual = (r1 >> (256 - i)).to_f64();
      let expected = (r1_top64 >> (64 - i)) as f64;
      assert_eq!(actual, expected, "exact mismatch at i={i}");
    }
  }

  #[rstest]
  fn to_f64_known_values() {
    assert_eq!(Arith256::ZERO.to_f64(), 0.0_f64);
    assert_eq!(Arith256::ONE.to_f64(), 1.0_f64);
    assert_eq!(Arith256::MAX.to_f64(), 1.157920892373162e77_f64);
    assert_eq!((Arith256::MAX >> 1u32).to_f64(), 5.78960446186581e76_f64);
    assert_eq!((Arith256::MAX >> 128u32).to_f64(), 3.402823669209385e38_f64);
    assert_eq!((Arith256::MAX >> (256 - 54) as u32).to_f64(), 1.8014398509481984e16_f64);
    // 53 bits and below should not use exponents
    assert_eq!((Arith256::MAX >> (256 - 53) as u32).to_f64(), 9007199254740991.0_f64);
    assert_eq!((Arith256::MAX >> (256 - 32) as u32).to_f64(), 4294967295.0_f64);
    assert_eq!((Arith256::MAX >> (256 - 16) as u32).to_f64(), 65535.0_f64);
    assert_eq!((Arith256::MAX >> (256 - 8) as u32).to_f64(), 255.0_f64);
  }

  #[rstest]
  #[case(Arith256::ZERO, 0)]
  #[case(Arith256::ONE, 1)]
  #[case(Arith256::from_u64(0x80), 8)]
  #[case(Arith256::from_u64(0x100), 9)]
  #[case(Arith256::MAX, 256)]
  fn bits(#[case] value: Arith256, #[case] expected: u32) {
    assert_eq!(value.bits(), expected);
  }

  #[rstest]
  fn bits_high_limb() {
    assert_eq!(Arith256::from_u128(1u128 << 127).bits(), 128);
  }

  #[rstest]
  fn bits_ported() {
    assert_eq!(Arith256::from(255_u64).bits(), 8);
    assert_eq!(Arith256::from(256_u64).bits(), 9);
    assert_eq!(Arith256::from(300_u64).bits(), 9);
    assert_eq!(Arith256::from(60000_u64).bits(), 16);
    assert_eq!(Arith256::from(70000_u64).bits(), 17);

    let u = Arith256::from(u128::MAX) << 1u32;
    assert_eq!(u.bits(), 129);

    let mut shl = Arith256::from(70000_u64);
    shl <<= 100u32;
    assert_eq!(shl.bits(), 117);
    shl <<= 100u32;
    assert_eq!(shl.bits(), 217);
    shl <<= 100u32;
    assert_eq!(shl.bits(), 0);
  }

  /// Each `(1 << i) != Zero` and `R1 ^ (1 << i) != R1`.
  #[rstest]
  fn shifted_one_nonzero(r1: Arith256) {
    let tmp64 = 0xc4dab720d9c7acaa_u64;
    for i in 0..256u32 {
      assert_ne!(Arith256::ZERO, Arith256::ONE << i);
      assert_ne!(r1, r1 ^ (Arith256::ONE << i));
      assert_ne!(
        Arith256::from_u64(tmp64) ^ (Arith256::ONE << i),
        Arith256::from_u64(tmp64)
      );
    }
  }
}

mod mul_u64 {
  use super::*;

  #[rstest]
  fn by_one() {
    let v = Arith256::from(0xDEAD_BEEF_DEAD_BEEF_u64);
    assert_eq!(v.mul_u64(1).0, v);
  }

  #[rstest]
  fn by_zero() {
    let v = Arith256::from(0xDEAD_BEEF_DEAD_BEEF_u64);
    assert_eq!(v.mul_u64(0).0, Arith256::ZERO);
  }

  #[rstest]
  fn chain() {
    let u64_val = Arith256::from(0xDEAD_BEEF_DEAD_BEEF_u64);

    let u96_res = u64_val.mul_u64(0xFFFF_FFFF).0;
    let u128_res = u96_res.mul_u64(0xFFFF_FFFF).0;
    let u160_res = u128_res.mul_u64(0xFFFF_FFFF).0;
    let u192_res = u160_res.mul_u64(0xFFFF_FFFF).0;
    let u224_res = u192_res.mul_u64(0xFFFF_FFFF).0;
    let u256_res = u224_res.mul_u64(0xFFFF_FFFF).0;

    assert_eq!(u96_res, from_array([0, 0, 0xDEAD_BEEE, 0xFFFF_FFFF_2152_4111]));
    assert_eq!(
      u128_res,
      from_array([0, 0, 0xDEAD_BEEE_2152_4110, 0x2152_4111_DEAD_BEEF])
    );
    assert_eq!(
      u160_res,
      from_array([0, 0xDEAD_BEED, 0x42A4_8222_0000_0001, 0xBD5B_7DDD_2152_4111])
    );
    assert_eq!(
      u192_res,
      from_array([0, 0xDEAD_BEEC_63F6_C334, 0xBD5B_7DDF_BD5B_7DDB, 0x63F6_C333_DEAD_BEEF])
    );
    assert_eq!(
      u224_res,
      from_array([
        0xDEAD_BEEB,
        0x8549_0448_5964_BAAA,
        0xFFFF_FFFB_A69B_4558,
        0x7AB6_FBBB_2152_4111
      ])
    );
    assert_eq!(
      u256_res,
      from_array([
        0xDEAD_BEEA_A69B_455C,
        0xD41B_B662_A69B_4550,
        0xA69B_455C_D41B_B662,
        0xA69B_4555_DEAD_BEEF,
      ])
    );
  }

  #[rstest]
  fn overflow_detection() {
    let (_, overflow) = Arith256::MAX.mul_u64(2);
    assert!(overflow, "max * 2 should overflow");

    let (_, overflow) = Arith256::ONE.mul_u64(1);
    assert!(!overflow, "one * 1 should not overflow");
  }
}

mod wrapping_inc {
  use super::*;

  #[rstest]
  fn basic() {
    assert_eq!(Arith256::ZERO.wrapping_inc(), Arith256::ONE);
    assert_eq!(Arith256::MAX.wrapping_inc(), Arith256::ZERO);
  }

  #[rstest]
  fn cross_limb_boundary() {
    let mut val = from_array([
      0xEFFF_FFFF_FFFF_FFFF,
      0xFFFF_FFFF_FFFF_FFFF,
      0xFFFF_FFFF_FFFF_FFFF,
      0xFFFF_FFFF_FFFF_FFFE,
    ]);
    val = val.wrapping_inc();
    assert_eq!(
      val,
      from_array([
        0xEFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
      ])
    );
    val = val.wrapping_inc();
    assert_eq!(
      val,
      from_array([
        0xF000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
      ])
    );
  }
}

mod inverse {
  use super::*;

  #[rstest]
  fn zero_min_max() {
    assert_eq!(Arith256::MAX.inverse(), Arith256::ONE);
    assert_eq!(Arith256::ONE.inverse(), Arith256::MAX);
    assert_eq!(Arith256::ZERO.inverse(), Arith256::MAX);
  }
}

mod formatting {
  use super::*;

  #[rstest]
  fn lower_hex() {
    assert_eq!(
      format!("{:x}", Arith256::from(0xDEADBEEF_u64)),
      "00000000000000000000000000000000000000000000000000000000deadbeef",
    );
    assert_eq!(
      format!("{:#x}", Arith256::from(0xDEADBEEF_u64)),
      "0x00000000000000000000000000000000000000000000000000000000deadbeef",
    );
    assert_eq!(
      format!("{:x}", Arith256::MAX),
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    assert_eq!(
      format!("{:#x}", Arith256::MAX),
      "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
  }

  #[rstest]
  fn upper_hex() {
    assert_eq!(
      format!("{:X}", Arith256::from(0xDEADBEEF_u64)),
      "00000000000000000000000000000000000000000000000000000000DEADBEEF",
    );
    assert_eq!(
      format!("{:#X}", Arith256::from(0xDEADBEEF_u64)),
      "0x00000000000000000000000000000000000000000000000000000000DEADBEEF",
    );
    assert_eq!(
      format!("{:X}", Arith256::MAX),
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    );
    assert_eq!(
      format!("{:#X}", Arith256::MAX),
      "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    );
  }
}
