use crate::mod_q;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use falcon_rust::{NTTPolynomial, Polynomial, LOG_N, N};
use std::ops::{Add, Mul};

#[derive(Debug, Clone)]
pub struct PolyVar<F: PrimeField>(pub Vec<FpVar<F>>);

impl<F: PrimeField> Add for PolyVar<F> {
  type Output = Self;

  fn add(self, other: Self) -> <Self as Add<Self>>::Output {
    let mut res = Vec::new();
    for (a, b) in self.0.iter().zip(other.0.iter()) {
      res.push(a.clone() + b.clone())
    }
    Self(res)
  }
}

impl<F: PrimeField> Mul for PolyVar<F>  {
    type Output = Self;

    fn mul(self, other: Self) -> <Self as Mul<Self>>::Output {
      let mut res = Vec::new();
      for (a, b) in self.0.iter().zip(other.0.iter()) {
        res.push(a.clone() * b.clone())
      }
      Self(res)
    }
}

impl<F: PrimeField> PolyVar<F> {
  pub fn new(coeff: Vec<FpVar<F>>) -> Self {
    Self(coeff)
  }

  pub fn alloc_vars(
    cs: impl Into<Namespace<F>>,
    poly: &Polynomial,
    mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    let ns = cs.into();
    let cs = ns.cs();
    let mut vec = Vec::new();
    for &value in poly.coeff().iter() {
      vec.push(FpVar::new_variable(
        cs.clone(),
        || Ok(F::from(value)),
        mode,
      )?);
    }
    Ok(Self(vec))
  }

  pub fn coeff(&self) -> &[FpVar<F>] {
    &self.0
  }
}

#[derive(Debug, Clone)]
pub struct NTTPolyVar<F: PrimeField>(pub Vec<FpVar<F>>);

impl<F: PrimeField> Add for NTTPolyVar<F> {
    type Output = Self;

    fn add(self, other: Self) -> <Self as Add<Self>>::Output {
      let mut res = Vec::new();
      for (a, b) in self.0.iter().zip(other.0.iter()) {
        res.push(a.clone() + b.clone())
      }
      Self(res)
    }
}

impl<F: PrimeField> Mul for NTTPolyVar<F> {
  type Output = Self;

  fn mul(self, other: Self) -> <Self as Mul<Self>>::Output {
    let mut res = Vec::new();
    for (a, b) in self.0.iter().zip(other.0.iter()) {
      res.push(a.clone() * b.clone())
    }
    Self(res)
  }
}

impl<F: PrimeField> NTTPolyVar<F> {
  pub fn new(coeff: Vec<FpVar<F>>) -> Self {
    Self(coeff)
  }

  pub fn alloc_vars(
    cs: impl Into<Namespace<F>>,
    poly: &NTTPolynomial,
    mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    let ns = cs.into();
    let cs = ns.cs();
    let mut vec = Vec::new();
    for &value in poly.coeff().iter() {
      vec.push(FpVar::new_variable(
        cs.clone(),
        || Ok(F::from(value)),
        mode,
      )?);
    }
    Ok(Self(vec))
  }

  pub fn coeff(&self) -> &[FpVar<F>] {
    &self.0
  }

  pub fn ntt_circuit(
    cs: ConstraintSystemRef<F>,
    input: &PolyVar<F>,
    const_vars: &[FpVar<F>],
    param: &[FpVar<F>],
  ) -> Result<Self, SynthesisError> {
    let mut output = Self::ntt_circuit_defer_range_check(input, const_vars, param)?;

    for e in output.0.iter_mut() {
      *e = mod_q(cs.clone(), e, &const_vars[0])?;
    }

    Ok(output)
  }

  pub fn ntt_circuit_defer_range_check(
    input: &PolyVar<F>,
    const_vars: &[FpVar<F>],
    param: &[FpVar<F>]
  ) -> Result<Self, SynthesisError> {
    if input.coeff().len() != N {
      panic!("Input length {} is not N", input.coeff().len())
    }
    let mut output = input.coeff().to_vec();

    let mut t = N;
    for l in 0..LOG_N {
      let m = 1 << l;
      let ht = t / 2;
      let mut i = 0;
      let mut j1 = 0;
      while i < m {
        let s = param[m + i].clone();
        let j2 = j1 + ht;
        let mut j = j1;
        while j < j2 {
          let u = output[j].clone();
          let v = &output[j + ht] * &s;
          let neg_v = &const_vars[l + 1] - &v;

          output[j] = &u + &v;
          output[j + ht] = &u + &neg_v;
          j += 1;
        }
        i += 1;
        j1 += t;
      }
      t = ht;
    }

    Ok(NTTPolyVar(output.to_vec()))
  }
}