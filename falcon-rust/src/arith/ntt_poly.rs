use super::ntt;
use crate::{Polynomial, MODULUS, N, U32_SAMPLE_THRESHOLD};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use std::ops::{Add, Mul, Sub};

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct NTTPolynomial(pub(crate) [u16; N]);

impl Default for NTTPolynomial {
  fn default() -> Self {
    Self([0u16; N])
  }
}

impl From<&Polynomial> for NTTPolynomial {
  fn from(poly: &Polynomial) -> Self {
    ntt(poly)
  }
}

impl Mul for NTTPolynomial {
  type Output = Self;
  fn mul(self, other: Self) -> <Self as Mul<Self>>::Output {
    let mut res = self;
    res.0
      .iter_mut()
      .zip(other.0.iter())
      .for_each(|(x, y)| *x = ((*x as u32 * *y as u32) % MODULUS as u32) as u16);
    res
  }
}

impl Add for NTTPolynomial {
  type Output = Self;
  fn add(self, other: Self) -> <Self as Add<Self>>::Output {
    let mut res = self;
    res.0
      .iter_mut()
      .zip(other.0.iter())
      .for_each(|(x, y)| *x = (*x + *y) % MODULUS as u16);
    res
  }
}

impl Sub for NTTPolynomial {
  type Output = Self;
  fn sub(self, other: Self) -> <Self as Add<Self>>::Output {
    let mut res = self;
    res.0
      .iter_mut()
      .zip(other.0.iter())
      .for_each(|(x, y)| *x = (*x + MODULUS as u16 - *y) % MODULUS as u16);
    res
  }
}

impl NTTPolynomial {
  pub fn from_hash_of_message(message: &[u8], nonce: &[u8]) -> Self {
    (&Polynomial::from_hash_of_message(message, nonce)).into()
  }

  pub fn rand<R:RngCore + CryptoRng>(rng: &mut R) -> Self {
    let mut res = [0u16; N];
    for e in res.iter_mut() {
      let mut tmp = rng.next_u32();
      while tmp >= U32_SAMPLE_THRESHOLD {
        tmp = rng.next_u32();
      }
      *e = (tmp % MODULUS as u32) as u16;
    }
    Self(res)
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let poly: Polynomial = self.into();
    poly.to_bytes()
  }

  pub fn from_seed(seed: &[u8; 32]) -> Self {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    Self::rand(&mut rng)
  }

  pub fn neg_mod_q(&self) -> Self {
    let mut res = *self;
    for e in res.0.iter_mut() {
      *e = MODULUS as u16 - *e;
    }
    res
  }

  pub fn coeff(&self) -> &[u16; N] {
    &self.0
  }
}

#[test]
fn test_ntt_conversion() {
  let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
  for _ in 0..100 {
    let t =  Polynomial::rand(&mut rng);
    let t_ntt: NTTPolynomial = (&t).into();
    let t_rec = (&t_ntt).into();

    assert_eq!(t, t_rec)
  }
}