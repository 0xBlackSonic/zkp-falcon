# Falcon R1CS

R1CS circuit for Falcon signature verification.

## Build

#### To build for falcon-512

```
cargo build
```

#### To build for falcon-1024

```
cargo build --features=falcon-1024 --no-default-reatures
```

#### To generate the `proving key`, `verification key` and the `solidity verifier`

```
cargo run
```

#### Generate WebAssembly artifacts (WIP)

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

## On-chain verification

In order to performe an on-chain verification it is necessary to generate a `tuple` with the proof data ontained, and an `uint256` array with the public inputs for the circuit.

### Tuple

It must be generated with the obtained proof data, and consist of the pairing points G1 and G2. The structure of the tuple must be:

```rust
// Tuple structure for Remix IDE

[
  [proof.a.x, proof.a.y],
  [
    [proof.b.x.c0, proof.b.x.c1],
    [proof.b.y.c0, proof.b.y.c1]
  ],
  [proof.c.x, proof.c.y]
]
```

### Public inputs

The public inputs consists of a 3-values uint256 array:

- Public key NTT polynomial hash
- Hashed message NTT polynomial hash
- Public key hash

The structure of this array must be:

```rust
[hash(pk_ntt), hash(hm_ntt), hash(pk)]
```
