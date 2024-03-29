pub const MODULUS: u16 = 12289;

// (q-1)/2
pub const MODULUS_MINUS_1_OVER_TWO: u16 = 6144;

// Larger multiple of q that is smaller tha 2^16
pub const MODULUS_THRESHOLD: u16 = 61445;

// Largest multiple of q that is smaller than 2^32
pub const U32_SAMPLE_THRESHOLD: u32 = 4294956344;

#[cfg(feature = "falcon-1024")]
pub use param1024::*;

#[cfg(feature = "falcon-512")]
pub use param512::*;

mod param512 {
  #![allow(dead_code)]
  pub const LOG_N: usize = 9;
  pub const N: usize = 512;
  pub const ONE_OVER_N: u32 = 12265;

  pub const PK_LEN: usize = 897;
  pub const SK_LEN: usize = 1281;
  pub const SIG_LEN: usize = 666;

  pub const KEYGEN_BUF_LEN: usize = 15879;
  pub const SIGN_BUF_LEN: usize = 39943;
  pub const MAKE_PK_BUF_LEN: usize = 3073;
  pub const VERIFY_BUF_LEN: usize = 4097;

  pub const SIG_L2_BOUND: u64 = 34034726;
}

mod param1024 {
  #![allow(dead_code)]
  pub const LOG_N: usize = 10;
  pub const N: usize = 1024;
  pub const ONE_OVER_N: u32 = 12277;

  pub const PK_LEN: usize = 1793;
  pub const SK_LEN: usize = 2305;
  pub const SIG_LEN: usize = 1280;

  pub const KEYGEN_BUF_LEN: usize = 31751;
  pub const SIGN_BUF_LEN: usize = 79879;
  pub const MAKE_PK_BUF_LEN: usize = 6145;
  pub const VERIFY_BUF_LEN: usize = 8193;

  pub const SIG_L2_BOUND: u64 = 70265242;
}