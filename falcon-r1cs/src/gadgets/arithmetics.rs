use super::*;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use falcon_rust::MODULUS;
use num_bigint::BigUint;

#[allow(dead_code)]
pub fn mod_q<F: PrimeField>(
  cs: ConstraintSystemRef<F>,
  a: &FpVar<F>,
  modulus_var: &FpVar<F>
) -> Result<FpVar<F>, SynthesisError> {
  let a_val = if cs.is_in_setup_mode() {
    F::one()
  } else {
    a.value()?
  };

  let a_int: BigUint = a_val.into();

  let modulus_int: BigUint = F::from(MODULUS).into();
  let t_int = &a_int / &modulus_int;
  let b_int = &a_int % &modulus_int;

  let t_val = F::from(t_int);
  let b_val = F::from(b_int);

  let t_var = FpVar::<F>::new_witness(cs.clone(), || Ok(t_val))?;
  let b_var = FpVar::<F>::new_witness(cs.clone(), || Ok(b_val))?;

  let t_12289 = t_var * modulus_var;
  let left = a - t_12289;
  left.enforce_equal(&b_var)?;

  enforce_less_than_q(cs, &b_var)?;

  Ok(b_var)
}

#[allow(dead_code)]
pub(crate) fn add_mod<F: PrimeField>(
  cs: ConstraintSystemRef<F>,
  a: &FpVar<F>,
  b: &FpVar<F>,
  modulus_var: &FpVar<F>
) -> Result<FpVar<F>, SynthesisError> {
  let a_val = if cs.is_in_setup_mode() {
    F::one()
  } else {
    a.value()?
  };

  let b_val = if cs.is_in_setup_mode() {
    F::one()
  } else {
    b.value()?
  };

  let ab_val = a_val + b_val;
  let ab_int: BigUint = ab_val.into();

  let modulus_int: BigUint = F::from(MODULUS).into();
  let c_int = &ab_int % &modulus_int;
  let t_int = (&ab_int - &c_int) / &modulus_int;

  let t_val = F::from(t_int);
  let c_val = F::from(c_int);

  // cast the variables
  let t_var = FpVar::<F>::new_witness(cs.clone(), || Ok(t_val))?;
  let c_var = FpVar::<F>::new_witness(cs.clone(), || Ok(c_val))?;

  // (1) a + b - t * 12289 = c
  let ab_var = a + b;
  let t_q = t_var * modulus_var;
  let left = ab_var - t_q;
  left.enforce_equal(&c_var)?;

  // (2) c < 12289
  enforce_less_than_q(cs, &c_var)?;

  Ok(c_var)
}