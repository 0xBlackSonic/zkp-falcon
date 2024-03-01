use ark_bn254::Bn254;
use ark_groth16::{create_random_proof, verify_proof, Groth16, PreparedVerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use falcon_r1cs::{hash_from_pk, hash_from_poly, FalconVerificationCircuit};
use falcon_rust::{KeyPair, NTTPolynomial, Polynomial};
use rand_chacha::ChaCha20Rng;

fn main() {
  let mut rng = ChaCha20Rng::from_seed([0; 32]);

  let keypair = KeyPair::keygen();

  let msg = "Testing message";
  let sig = keypair
    .secret_key
    .sign(msg.as_ref());
  assert!(keypair.public_key.verify(msg.as_ref(), &sig));

  let cs_input =  FalconVerificationCircuit::build_circuit(
    keypair.public_key,
    msg.as_bytes().to_vec(),
    sig
  );

  let (pp, vk) = Groth16::<Bn254>::circuit_specific_setup(cs_input.clone(), &mut rng).unwrap();
  let proof = create_random_proof(cs_input, &pp, &mut rng).unwrap();
  let pk = Polynomial::from(&(keypair.public_key));
  let pk_ntt = NTTPolynomial::from(&pk);
  let hm = Polynomial::from_hash_of_message(msg.as_ref(), sig.nonce());
  let hm_ntt = NTTPolynomial::from(&hm);
  
  let mut pub_input = Vec::new();
  pub_input.push(hash_from_poly(&pk_ntt).unwrap());
  pub_input.push(hash_from_poly(&hm_ntt).unwrap());
  pub_input.push(hash_from_pk(&pk).unwrap());

  let pvk = PreparedVerifyingKey::from(vk.clone());

  assert!(verify_proof(&pvk, &proof, &pub_input).unwrap())

}
