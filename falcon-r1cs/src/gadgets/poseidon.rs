use ark_ff::{Fp256, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use falcon_rust::{NTTPolynomial, N, Polynomial};
use ark_bn254::{Fr, FrParameters};
use arkworks_native_gadgets::poseidon::{
  sbox::PoseidonSbox, FieldHasher, Poseidon, PoseidonParameters,
};
use arkworks_utils::{
  bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
};

pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
  let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

  let mds_f = bytes_matrix_to_f(&pos_data.mds);
  let rounds_f = bytes_vec_to_f(&pos_data.rounds);

  PoseidonParameters {
    mds_matrix: mds_f,
    round_keys: rounds_f,
    full_rounds: pos_data.full_rounds,
    partial_rounds: pos_data.partial_rounds,
    sbox: PoseidonSbox(pos_data.exp),
    width: pos_data.width,
  }
}

/**
 * Poseidon hash circuit vars
 */
#[derive(Debug, Clone)]
pub struct PoseidonVars<Fr: PrimeField>(pub FpVar<Fr>);

impl<Fr: PrimeField> PoseidonVars<Fr> {
  pub fn new(coeff: FpVar<Fr>) -> Self {
    Self(coeff)
  }

  pub fn hash_poly(
    cs: impl Into<Namespace<Fr>>,
    poly: &NTTPolynomial,
    mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    let curve = Curve::Bn254;
    let ns = cs.into();
    let cs = ns.cs();

    let mut inputs = Vec::new();
    for e in poly.coeff() {
      inputs.push(Fr::from(*e))
    }

    let parameters =  setup_params(curve, 5, 3);
    let hasher = Poseidon::<Fr>::new(parameters);

    let mut res = hasher.hash(&[inputs[0], inputs[1]]).unwrap();
    for &value in &inputs[2..N] {
      res = hasher.hash(&[res, value]).unwrap();
    }
    
    Ok(Self(FpVar::new_variable(cs.clone(), || Ok(Fr::from(res)), mode)?))
  }

  pub fn hash_pubic_key(
    cs: impl Into<Namespace<Fr>>,
    poly: &Polynomial,
    mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    let curve = Curve::Bn254;
    let ns = cs.into();
    let cs = ns.cs();

    let mut inputs = Vec::new();
    for e in poly.coeff() {
      inputs.push(Fr::from(*e))
    }

    let parameters =  setup_params(curve, 5, 3);
    let hasher = Poseidon::<Fr>::new(parameters);

    let mut res = hasher.hash(&[inputs[0], inputs[1]]).unwrap();
    for &value in &inputs[2..N] {
      res = hasher.hash(&[res, value]).unwrap();
    }
    
    Ok(Self(FpVar::new_variable(cs.clone(), || Ok(Fr::from(res)), mode)?))
  }

  pub fn coeff(&self) -> &FpVar<Fr> {
    &self.0
  }
}

/**
 * Poseidon Hash for NTTPolynomial
 */
type PoseidonHasher = Poseidon<Fr>;
pub fn hash_from_poly(poly: &NTTPolynomial) -> Result<Fp256<FrParameters>, SynthesisError> {
  let curve = Curve::Bn254;

  let mut inputs = Vec::new();
  for e in poly.coeff() {
    inputs.push(Fr::from(*e))
  }

  let parameters = setup_params(curve, 5, 3);
  let hasher = PoseidonHasher::new(parameters);

  let mut res = hasher.hash(&[inputs[0], inputs[1]]).unwrap();
  for &value in &inputs[2..N] {
    res = hasher.hash(&[res, value]).unwrap();
  }

  Ok(res)
}

/**
 * Poseidon hash for Polynomial
 */
pub fn hash_from_pk(poly: &Polynomial) -> Result<Fp256<FrParameters>, SynthesisError> {
  let curve = Curve::Bn254;

  let mut inputs = Vec::new();
  for e in poly.coeff() {
    inputs.push(Fr::from(*e));
  }

  let parameters = setup_params(curve, 5, 3);
  let hasher = PoseidonHasher::new(parameters);

  let mut res = hasher.hash(&[inputs[0], inputs[1]]).unwrap();
  for &value in &inputs[2..N] {
    res = hasher.hash(&[res, value]).unwrap();
  }

  Ok(res)
}

#[cfg(test)]
pub mod test {
  use ark_bn254::Fr;
  use ark_ff::{fields::Field, PrimeField};
  use ark_std::One;
  use arkworks_native_gadgets::poseidon::{
		sbox::PoseidonSbox, FieldHasher, Poseidon, PoseidonParameters,
	};

  use arkworks_utils::{
		bytes_matrix_to_f, bytes_vec_to_f, parse_vec, poseidon_params::setup_poseidon_params, Curve
	};

  pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
		let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

		let mds_f = bytes_matrix_to_f(&pos_data.mds);
		let rounds_f = bytes_vec_to_f(&pos_data.rounds);

		let pos = PoseidonParameters {
			mds_matrix: mds_f,
			round_keys: rounds_f,
			full_rounds: pos_data.full_rounds,
			partial_rounds: pos_data.partial_rounds,
			sbox: PoseidonSbox(pos_data.exp),
			width: pos_data.width,
		};

		pos
	}

  type PoseidonHasher = Poseidon<Fr>;
  #[test]
  fn should_verify_poseidon() {
    let curve = Curve::Bn254;

    let res: Vec<Fr> = bytes_vec_to_f(
			&parse_vec(vec![
				"0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a",
			])
			.unwrap(),
		);
  
    let parameters = setup_params(curve, 5, 3);
    let hasher = PoseidonHasher::new(parameters);

    let left_input = Fr::one();
		let right_input = Fr::one().double();
		let poseidon_res = hasher.hash_two(&left_input, &right_input).unwrap();

    assert_eq!(res[0], poseidon_res, "{} != {}", res[0], poseidon_res);
  }
}
