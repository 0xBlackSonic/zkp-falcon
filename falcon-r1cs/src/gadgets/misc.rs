use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use falcon_rust::{N, NTT_TABLE};

use crate::is_less_than_6144;

pub fn ntt_param_var<F: PrimeField>(cs: ConstraintSystemRef<F>) -> Result<Vec<FpVar<F>>, SynthesisError> {
  let mut res = Vec::new();

  for e in NTT_TABLE[0..N].as_ref() {
    res.push(FpVar::<F>::new_constant(cs.clone(), F::from(*e))?)
  }

  Ok(res)
}

pub fn enforce_decompose<F: PrimeField>(
  a: &FpVar<F>,
  bits: &[Boolean<F>],
) -> Result<(), SynthesisError> {
  if bits.is_empty() {
    panic!("Invalid input length: {}", bits.len());
  }

  let mut res: FpVar<F> = bits[bits.len() - 1].clone().into();
  for e in bits.iter().rev().skip(1) {
    res = res.double()? + FpVar::<F>::from(e.clone());
  }

  res.enforce_equal(a)?;
  Ok(())
}

pub fn l2_norm_var<F: PrimeField>(
  cs: ConstraintSystemRef<F>,
  input: &[FpVar<F>],
  modulus_var: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
  let mut res = FpVar::<F>::conditionally_select(
      &is_less_than_6144(cs.clone(), &input[0])?,
      &input[0],
      &(modulus_var - &input[0]),
  )?;
  res = &res * &res;
  for e in input.iter().skip(1) {
      let tmp = FpVar::<F>::conditionally_select(
          &is_less_than_6144(cs.clone(), e)?,
          e,
          &(modulus_var - e),
      )?;
      res += &tmp * &tmp
  }

  Ok(res)
}