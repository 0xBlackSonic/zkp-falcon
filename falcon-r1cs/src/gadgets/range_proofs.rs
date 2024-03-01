use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
#[cfg(not(test))]
use falcon_rust::MODULUS;
#[cfg(not(test))]
use falcon_rust::SIG_L2_BOUND;

use crate::enforce_decompose;

pub(crate) fn enforce_less_than_q<F: PrimeField>(
  cs: ConstraintSystemRef<F>,
  a: &FpVar<F>,
) -> Result<(), SynthesisError> {
  let a_val = if cs.is_in_setup_mode() {
    F::one()
  } else {
    a.value()?
  };

  #[cfg(not(test))]
  if a_val >= F::from(MODULUS) {
    panic!("Invalid input: {}", a_val);
  }

  let a_bits = a_val.into_repr().to_bits_le();
  let a_bit_vars = a_bits
    .iter()
    .take(14)
    .map(|x| Boolean::new_witness(cs.clone(), || Ok(x)))
    .collect::<Result<Vec<_>, _>>()?;

  enforce_decompose(a, a_bit_vars.as_ref())?;

  (a_bit_vars[13].is_eq(&Boolean::FALSE)?)
    .or(
        &a_bit_vars[12].is_eq(&Boolean::FALSE)?.or(
          &Boolean::kary_or(a_bit_vars[0..12].as_ref())?.is_eq(&Boolean::FALSE)?,
        )?,
    )?
    .enforce_equal(&Boolean::TRUE)?;

  Ok(())
}

pub(crate) fn is_less_than_6144<F: PrimeField>(
  cs: ConstraintSystemRef<F>,
  a: &FpVar<F>,
) -> Result<Boolean<F>, SynthesisError> {

  let a_val = if cs.is_in_setup_mode() {
      F::one()
  } else {
      a.value()?
  };

  let a_bits = a_val.into_repr().to_bits_le();
  let a_bit_vars = a_bits
      .iter()
      .take(14)
      .map(|x| Boolean::new_witness(cs.clone(), || Ok(x)))
      .collect::<Result<Vec<_>, _>>()?;

  enforce_decompose(a, a_bit_vars.as_ref())?;

  let res = (a_bit_vars[13].is_eq(&Boolean::FALSE)?)
      .and(&a_bit_vars[12].is_eq(&Boolean::FALSE)?
      .   or(&a_bit_vars[11].is_eq(&Boolean::FALSE)?
          )?
      )?
      .is_eq(&Boolean::TRUE);
  res
}

pub fn enforce_less_than_norm_bound<F: PrimeField>(
  cs: ConstraintSystemRef<F>,
  a: &FpVar<F>,
) -> Result<(), SynthesisError> {
  #[cfg(feature = "falcon-512")]
  enforce_less_than_norm_bound_512(cs, a)?;
  #[cfg(feature = "falcon-1024")]
  enforce_less_than_norm_bound_1024(cs, a)?;

  Ok(())
}

#[cfg(feature = "falcon-512")]
fn enforce_less_than_norm_bound_512<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let a_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        a.value()?
    };

    #[cfg(not(test))]
    if a_val >= F::from(SIG_L2_BOUND) {
        panic!("Invalid input: {}", a_val);
    }

    let a_bits = a_val.into_repr().to_bits_le();
    let a_bit_vars = a_bits
        .iter()
        .take(26)
        .map(|x| Boolean::new_witness(cs.clone(), || Ok(x)))
        .collect::<Result<Vec<_>, _>>()?;

    enforce_decompose(a, a_bit_vars.as_ref())?;

    #[rustfmt::skip]
    (a_bit_vars[25].is_eq(&Boolean::FALSE)?).or(
        &Boolean::kary_or(a_bit_vars[19..25].as_ref())?.is_eq(&Boolean::FALSE)?.and(
            &Boolean::kary_and(a_bit_vars[16..19].as_ref())?.is_eq(&Boolean::FALSE)?.or(
                &a_bit_vars[15].is_eq(&Boolean::FALSE)?.and(
                        &a_bit_vars[14].is_eq(&Boolean::FALSE)?.or(
                            &a_bit_vars[13].is_eq(&Boolean::FALSE)?.and(
                                &a_bit_vars[12].is_eq(&Boolean::FALSE)?.or(
                                    &a_bit_vars[11].is_eq(&Boolean::FALSE)?.and(
                                        &a_bit_vars[10].is_eq(&Boolean::FALSE)?.or(
                                            &Boolean::kary_or(a_bit_vars[6..10].as_ref())?.is_eq(&Boolean::FALSE)?.and(
                                                &a_bit_vars[5].is_eq(&Boolean::FALSE)?.or(
                                                    &Boolean::kary_or(a_bit_vars[3..5].as_ref())?.is_eq(&Boolean::FALSE)?.and(
                                                        &Boolean::kary_and(a_bit_vars[1..3].as_ref())?.is_eq(&Boolean::FALSE)?
                                                    )?
                                                )?
                                            )?
                                        )?
                                    )?
                                )?
                            )?
                        )?
                    )? 
                )?,
            )?,
        )?.enforce_equal(&Boolean::TRUE)?;
    Ok(())
}
   
#[cfg(feature = "falcon-1024")]
fn enforce_less_than_norm_bound_1024<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let a_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        a.value()?
    };

    #[cfg(not(test))]
    if a_val >= F::from(SIG_L2_BOUND) {
        panic!("Invalid input: {}", a_val);
    }

    let a_bits = a_val.into_repr().to_bits_le();
    let a_bit_vars = a_bits
        .iter()
        .take(27)
        .map(|x| Boolean::new_witness(cs.clone(), || Ok(x)))
        .collect::<Result<Vec<_>, _>>()?;

    enforce_decompose(a, a_bit_vars.as_ref())?;

    #[rustfmt::skip]

    (a_bit_vars[26].is_eq(&Boolean::FALSE)?).or(
        &Boolean::kary_or(a_bit_vars[22..26].as_ref())?.is_eq(&Boolean::FALSE)?.and(
            &Boolean::kary_and(a_bit_vars[20..22].as_ref())?.is_eq(&Boolean::FALSE)?.or(
                &Boolean::kary_or(a_bit_vars[14..20].as_ref())?.is_eq(&Boolean::FALSE)?.and(
                    &a_bit_vars[13].is_eq(&Boolean::FALSE)?.or(
                        &a_bit_vars[12].is_eq(&Boolean::FALSE)?.and(
                            &a_bit_vars[11].is_eq(&Boolean::FALSE)?.or(
                                &Boolean::kary_or(a_bit_vars[9..11].as_ref())?.is_eq(&Boolean::FALSE)?.and(
                                    &Boolean::kary_and(a_bit_vars[7..9].as_ref())?.is_eq(&Boolean::FALSE)?.or(
                                        &Boolean::kary_or(a_bit_vars[5..7].as_ref())?.is_eq(&Boolean::FALSE)?.and(
                                            &Boolean::kary_and(a_bit_vars[3..5].as_ref())?.is_eq(&Boolean::FALSE)?.or(
                                                &Boolean::kary_or(a_bit_vars[1..3].as_ref())?.is_eq(&Boolean::FALSE)?
                                            )?
                                        )?
                                    )?
                                )?
                            )?
                        )?
                    )?
                )?
            )?,
        )?
    )?.enforce_equal(&Boolean::TRUE)?;
    Ok(())
}

