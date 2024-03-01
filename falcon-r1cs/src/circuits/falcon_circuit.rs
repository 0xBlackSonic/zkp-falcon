use crate::gadgets::*;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result};
use falcon_rust::*;

#[derive(Clone, Debug)]
pub struct FalconVerificationCircuit {
  pk: PublicKey,
  msg: Vec<u8>,
  sig: Signature
}

impl FalconVerificationCircuit {
  pub fn build_circuit(pk: PublicKey, msg: Vec<u8>, sig: Signature) -> Self {
    Self { pk, msg, sig }
  }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for FalconVerificationCircuit {
  fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<()> {
    let sig_poly: Polynomial = (&self.sig).into();
    let pk_poly: Polynomial = (&self.pk).into();

    let const_q_power_vars: Vec<FpVar<F>> = (1..LOG_N + 2)
      .map(|x| {
        FpVar::<F>::new_constant(
          cs.clone(), 
          F::from(1u32 << (x - 1)) * F::from(MODULUS).pow(&[x as u64]),
        )
        .unwrap()
      })
      .collect();
    let param_vars = ntt_param_var(cs.clone()).unwrap();

    let hm = Polynomial::from_hash_of_message(self.msg.as_ref(), self.sig.nonce());
    let hm_ntt = NTTPolynomial::from(&hm);

    let uh = sig_poly * pk_poly;
    let v: Polynomial = hm - uh;

    let pk_ntt = NTTPolynomial::from(&pk_poly);

    let sig_poly_vars = PolyVar::<F>::alloc_vars(cs.clone(), &sig_poly, AllocationMode::Witness)?;
    let pk_ntt_vars = NTTPolyVar::<F>::alloc_vars(cs.clone(), &pk_ntt, AllocationMode::Witness)?;
    let hm_ntt_vars = NTTPolyVar::<F>::alloc_vars(cs.clone(), &hm_ntt, AllocationMode::Witness)?;
    let v_vars = PolyVar::<F>::alloc_vars(cs.clone(), &v, AllocationMode::Witness)?;

    /*
      Compress public inputs
        - Reveal the G1 points' hash to the verifier.
        - Calculate the owner hash from public key with poseidon.
    */
    PoseidonVars::hash_poly(cs.clone(), &pk_ntt, AllocationMode::Input)?;
    PoseidonVars::hash_poly(cs.clone(), &hm_ntt, AllocationMode::Input)?;
    PoseidonVars::hash_pubic_key(cs.clone(), &pk_poly, AllocationMode::Input)?;

    for e in v_vars.coeff() {
      enforce_less_than_q(cs.clone(), &e)?;
    }

    let sig_ntt_vars = NTTPolyVar::ntt_circuit(cs.clone(), &sig_poly_vars, &const_q_power_vars, &param_vars)?;
    let v_ntt_vars = NTTPolyVar::ntt_circuit(cs.clone(), &v_vars, &const_q_power_vars, &param_vars)?;

    for i in 0..N {
      hm_ntt_vars.coeff()[i].enforce_equal(&add_mod(
        cs.clone(),
        &v_ntt_vars.coeff()[i],
        &(&sig_ntt_vars.coeff()[i] * &pk_ntt_vars.coeff()[i]),
        &const_q_power_vars[0],
      )?)?;
    }

    let l2_norm_var = l2_norm_var(
      cs.clone(),
      &[v_vars.coeff(), sig_poly_vars.coeff()].concat(),
      &const_q_power_vars[0],
    )?;

    enforce_less_than_norm_bound(cs, &l2_norm_var)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use ark_ed_on_bn254::fq::Fq;
  use ark_relations::r1cs::ConstraintSystem;
  
  #[test]
  fn test_verification_r1cs() {
    let keypair = KeyPair::keygen();
    let message = "Testing message".as_bytes();
    let sig = keypair
      .secret_key
      .sign(message.as_ref());

    assert!(keypair.public_key.verify(message.as_ref(), &sig));
    assert!(keypair.public_key.verify_rust(message.as_ref(), &sig));
    
    let cs = ConstraintSystem::<Fq>::new_ref();

    let falcon_circuit = FalconVerificationCircuit {
      pk: keypair.public_key,
      msg: message.to_vec(),
      sig,
    };

    falcon_circuit.generate_constraints(cs.clone()).unwrap();
    println!(
      "number of variables {} {} and constraints {}\n",
      cs.num_instance_variables(),
      cs.num_witness_variables(),
      cs.num_constraints(),
    );

    assert!(cs.is_satisfied().unwrap());
  }
}
