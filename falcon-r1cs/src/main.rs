use std::{error::Error, fs};
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use arkworks_solidity_verifier::SolidityVerifier;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use falcon_r1cs::FalconVerificationCircuit;
use falcon_rust::KeyPair;

fn generate<C: ConstraintSynthesizer<Fr>>(circuit: C, label: &str) -> Result<(), Box<dyn Error>> {
    println!("Generating keys for {}", label);

    let mut rng = ChaCha20Rng::from_seed([0; 32]);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)?;
    let manifest_dir = env!("CARGO_MANIFEST_DIR");

    let mut pk_bytes = vec![];
    let mut vk_bytes = vec![];

    println!("Serializing keys for {}", label);
    pk.serialize_uncompressed(&mut pk_bytes)?;
    vk.serialize_uncompressed(&mut vk_bytes)?;

    println!("Writing key for {}", label);
    fs::write(format!("{}/out/{}_pk.bin", manifest_dir, label), pk_bytes)?;
    fs::write(format!("{}/out/{}_vk.bin", manifest_dir, label), vk_bytes)?;

    println!("Exporting verifier for {}", label);
    let verifier = Groth16::export(&vk);

    println!("Writing verifier for {}", label);
    fs::write(
        format!("{}/out/{}_verifier.sol", manifest_dir, label),
        verifier,
    )?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let dir = format!("{}/out", env!("CARGO_MANIFEST_DIR"));
    if fs::read_dir(&dir).is_err() {
        fs::create_dir(&dir)?;
    }

    let keypair = KeyPair::keygen();

    let msg = "Testing message";
    let sig = keypair
        .secret_key
        .sign(msg.as_ref());
    assert!(keypair.public_key.verify(msg.as_ref(), &sig));

    generate(
        FalconVerificationCircuit::build_circuit(
            keypair.public_key, 
            msg.as_bytes().to_vec(), 
            sig), 
        "Verification"
    )?;

    Ok(())
}
