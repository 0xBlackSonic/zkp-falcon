# Falcon R1CS

R1CS circuit for Falcon signature verification.

## Build

### To build for falcon-512

```
cargo build
```

### To build for falcon-1024

```
cargo build --features=falcon-1024 --no-default-reatures
```

### To generate the `proving key`, `verification key` and the solidity verifier

```
Cargo run
```

### Generate WebAssembly artifacts (WIP)

> It will provide a javascript bridge to interact with some functionalities.

## Example

`falcon-r1cs/examples/proof.rs` shows an example of how to generate a proof of knowledge of the signature. To run this example

```
cargo run --release --example proof
```

## Main changes

In order to perform the verification correctly, it is necessary that all G1 points are public, and in the case of falcon-512 a total of 1024 points would be needed, which is an inconvenience when performing an on-chain verification. To avoid this, a hash of each group of points is generated with Poseidon.

In order to be able to use the public key in a smart account, a Poseidon hash of the public key is used as public input because:

- The original length is 897 bytes for falcon-512, a compression of it would be needed.
- The original public key is not known to third parties.
