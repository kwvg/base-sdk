//! Proves Bazel can link a Rust DLL for another target, with C dependencies.

use core::ptr;

use dash_pkc::__deps::{blst, secp256k1};

#[unsafe(no_mangle)]
pub extern "C" fn rustdll_answer() -> u32 {
  // Each call reaches C, so the DLL fails to link if either library did not.
  let valid = secp256k1::SecretKey::from_secret_bytes([1; 32]).is_ok();
  let mut key = blst::blst_scalar::default();
  unsafe { blst::blst_keygen(&mut key, [7u8; 32].as_ptr(), 32, ptr::null(), 0) };
  u32::from(valid) + 41
}
