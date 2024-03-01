use super::sig::Signature;
use crate::{binder::*, param::*, NTTPolynomial, Polynomial};
use libc::c_void;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PublicKey(pub(crate) [u8; PK_LEN]);

impl PublicKey {
  pub fn as_bytes(&self) -> &[u8] {
    self.0.as_ref()
  }

  pub fn verify(&self, message: &[u8], sig: &Signature) -> bool {
    let sig_type = 2;
    let mut buf = [0u8; VERIFY_BUF_LEN];

    let res = unsafe {
      falcon_verify(
        sig.0.as_ptr() as *const c_void, 
        (sig.0.len() as u64).try_into().unwrap(), 
        sig_type, 
        self.0.as_ptr() as *const c_void, 
        (self.0.len() as u64).try_into().unwrap(), 
        message.as_ptr() as *const c_void, 
        (message.len() as u64).try_into().unwrap(), 
        buf.as_mut_ptr() as *mut c_void, 
        (VERIFY_BUF_LEN as u64).try_into().unwrap(),
      )
    };

    res == 0
  }

  pub fn unpack(&self) -> [u16; N] {
    assert!(self.0[0] == LOG_N as u8);
    mod_q_decode(self.0[1..].as_ref())
  }

  pub fn verify_rust(&self, message: &[u8], sig: &Signature) -> bool {
    let pk: Polynomial = self.into();
    let sig_u: Polynomial = sig.into();
    let hm = Polynomial::from_hash_of_message(message, sig.0[1..41].as_ref());

    // compute v = hm - uh
    let uh = sig_u * pk;
    let v = hm - uh;

    let l2_norm = sig_u.l2_norm() + v.l2_norm();
    l2_norm <= SIG_L2_BOUND
}
}

impl From<&PublicKey> for Polynomial {
  fn from(pk: &PublicKey) -> Self {
    Polynomial(pk.unpack())
  }
}

impl From<&PublicKey> for NTTPolynomial {
  fn from(pk: &PublicKey) -> Self {
    (&Polynomial(pk.unpack())).into()
  }
}

fn mod_q_decode(input: &[u8]) -> [u16; N] {
  if input.len() != (N * 14 + 7) / 8 {
    panic!("Incorrect input length")
  }

  let mut input_pr = 0;
  let mut acc = 0u32;
  let mut acc_len = 0;

  let mut output_ptr = 0;
  let mut output = [0u16; N];

  while output_ptr < N {
    acc = (acc << 8) | (input[input_pr] as u32);
    input_pr += 1;
    acc_len += 8;

    if acc_len >= 14 {
      acc_len -= 14;
      let w = (acc >> acc_len) & 0x3FFF;
      assert!(w < 12289, "Incorrect input {}", w);
      output[output_ptr] = w as u16;
      output_ptr += 1;
    }
  }

  if (acc & ((1u32 << acc_len) -1)) != 0 {
    panic!("Incorrect remaining data")
  }

  output
}