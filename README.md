<h1 align="center">Polynomial Commitments</h1>

<p align="center">
   <a href="https://github.com/arkworks-rs/poly-commit/blob/master/LICENSE-APACHE"><img src="https://img.shields.io/badge/license-APACHE-blue.svg"></a>
   <a href="https://github.com/arkworks-rs/poly-commit/blob/master/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

`poly-commit` is a Rust library that implements *polynomial commitment schemes*. This library was initially developed as part of the [Marlin paper][marlin], and is released under the MIT License and the Apache v2 License (see [License](#license)).

**WARNING:** This is an academic prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Overview

A polynomial commitment scheme is a cryptographic primitive that enables a party to commit to a polynomial over a given finite field, and then, later on, to reveal desired evaluations of the polynomial along with cryptographic proofs attesting to their correctness.

This library provides various constructions of polynomial commitment schemes. These constructions support committing to multiple polynomials at a time with differing degree bounds, batching multiple evaluation proofs for the same evaluation point into a single one, and batch verification of proofs.

The key properties satisfied by the polynomial commitment schemes are **succinctness**, **extractability**, and **hiding**. See [the Marlin paper][marlin] for definitions of these properties.


### Supported Polynomial Commitment Schemes

The library supports six polynomial commitment schemes.

#### Inner-product-argument PC

A polynomial commitment scheme based on the hardness of the discrete logarithm problem in prime-order groups. 
The construction is described in the following paper.

[pcd-acc]: https://ia.cr/2020/499

[Proof-Carrying Data from Accumulation Schemes][pcd-acc]     
Benedikt Bünz, Alessandro Chiesa, Pratyush Mishra, Nicholas Spooner     
TCC 2020

#### Marlin variant of the Kate-Zaverucha-Goldberg PC

Polynomial commitment based on the Kate-Zaverucha-Goldberg construction, with degree enforcement, batching, and (optional) hiding property taken from Marlin.
The construction is described in the following papers.

[Marlin: Preprocessing zkSNARKs with Universal and Updatable SRS][marlin]     
Alessandro Chiesa, Yuncong Hu, Mary Maller, Pratyush Mishra, Noah Vesely, Nicholas Ward  
EUROCRYPT 2020

[Polynomial Commitments][kzg10]     
Aniket Kate, Gregory M. Zaverucha, Ian Goldberg     
ASIACRYPT 2010

#### Sonic/AuroraLight variant of the Kate-Zaverucha-Goldberg PC

Polynomial commitment based on the Kate-Zaverucha-Goldberg construction, with degree enforcement and batching taken from Sonic (more precisely, their counterparts in AuroraLight that avoid negative G1 powers). The (optional) hiding property of the commitment scheme follows the approach described in Marlin.
The construction is described in the following papers.

[AuroraLight: Improved Prover Efficiency and SRS Size in a Sonic-Like System][aurora-light]     
Ariel Gabizon     
ePrint, 2019

[Sonic: Zero-Knowledge SNARKs from Linear-Size Universal and Updateable Structured Reference Strings][sonic]     
Mary Maller, Sean Bowe, Markulf Kohlweiss, Sarah Meiklejohn     
CCS 2019

[Marlin: Preprocessing zkSNARKs with Universal and Updatable SRS][marlin]     
Alessandro Chiesa, Yuncong Hu, Mary Maller, Pratyush Mishra, Noah Vesely, Nicholas Ward  
EUROCRYPT 2020

[Polynomial Commitments][kzg10]     
Aniket Kate, Gregory M. Zaverucha, Ian Goldberg     
ASIACRYPT 2010

#### Hyrax multilinear PC

Multilinear polynomial commitment, introduced with Hyrax zkSNARK. Relies on Pedersen commitments and discrete logarithm problem for a hiding scheme. Construction details in the following paper.

[Doubly-efficient zkSNARKs without trusted setup][hyrax]     
Riad S. Wahby, Ioanna Tzialla, abhi shelat, Justin Thaler, Michael Walfish     
2018 IEEE Symposium on Security and Privacy

#### Ligero and Brakedown

Polynomial commitments based on linear codes and cryptographic hash functions. Construction details in the following papers.

[Ligero: Lightweight Sublinear Arguments Without a Trusted Setup][ligero]    
Scott Ames, Carmit Hazay, Yuval Ishai, Muthuramakrishnan Venkitasubramaniam    
CCS 2017

[Brakedown: Linear-time and field-agnostic SNARKs for R1CS][brakedown]    
Alexander Golovnev, Jonathan Lee, Srinath Setty, Justin Thaler, Riad S. Wahby    
CRYPTO 2023

#### Marlin variant of the Papamanthou-Shi-Tamassia multivariate PC

Multivariate polynomial commitment based on the construction in the Papamanthou-Shi-Tamassia construction with batching and (optional) hiding property inspired by the univariate scheme in Marlin.
The construction is described in the following paper.

[Signatures of Correct Computation][pst]    
Charalampos Papamanthou, Elaine Shi, Roberto Tamassia   
TCC 2013

[Marlin: Preprocessing zkSNARKs with Universal and Updatable SRS][marlin]     
Alessandro Chiesa, Yuncong Hu, Mary Maller, Pratyush Mishra, Noah Vesely, Nicholas Ward  
EUROCRYPT 2020

### Comparison (WIP)

#### Comparison of `MarlinKZG10` and `SonicKZG10`


- High-level:
They handle degree bounds differently. 
MarlinPC uses shift powers only in G1 and requires two commitments to enforce degree bounds.
SonicPC uses shift powers in G1 and G2 and requires only one commitment to enforce degree bounds.

- Setup:
SonicPC additionally computes some G2 elements for shift powers: `(1/\beta)^i H`. This results in a longer verifying key, as shift powers in SonicPC are in G2, while shift powers in Marlin are in G1, and are shared with the "non-shift" powers.

- Commit:
When there is no degree bound, both are the same.
When there is a degree bound, MarlinPC is more expensive: it needs an additional commitment to commit to the shifted poynomial. 

- Open: 
When there is no degree bound, both are the same.
When there is a degree bound, MarlinPC is slightly more expensive: it requires more scalar field computations.

- Check:
MarlinPC simply adjusts the commitment of the shifted polynomial, so the overhead is small. It checks a pairing equation with two pairing operations.
SonicPC is more expensive, as it checks a pairing equation of three pairing operations. It can be reduced into two if there is no degree bound.

## Build guide

The library compiles on the `stable` toolchain of the Rust compiler. To install the latest version of Rust, first install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager. Once `rustup` is installed, install the Rust toolchain by invoking:
```bash
rustup install stable
```

After that, use `cargo` (the standard Rust build tool) to build the library:
```bash
git clone https://github.com/scipr-lab/poly-commit.git
cd poly-commit
cargo build --release
```

This library comes with some unit and integration tests. Run these tests with:
```bash
cargo test
```

A benchmarking module is also provided for the `commit`, `open` and `verify` methods, as well as for computing the commitment and proof size. You can add a new benchmark for your scheme following the examples in the `pcs/benches` directory, or run the existing benchmarks with:
```bash
cargo bench
```

Lastly, this library is instrumented with profiling infrastructure that prints detailed traces of execution time. To enable this, compile with `cargo build --features print-trace`.

## Usage

### [`PolynomialCommitment`](https://github.com/arkworks-rs/poly-commit/blob/master/src/lib.rs#L145)

This trait defines the interface for a polynomial commitment scheme. It is recommended to use the schemes from this crate that implement the `PolynomialCommitment` trait
(e.g. the [vanilla KZG scheme](./src/kzg10/mod.rs) does not implement this trait, but the [Marlin scheme](./src/marlin/mod.rs) which uses it under the hood, does).

```rust
// In this example, we will commit to a single polynomial, open it first at one point, and then batched at two points, and finally verify the proofs.
// We will use the KZG10 polynomial commitment scheme, following the approach from Marlin.

use ark_poly_commit::{Polynomial, marlin_pc::MarlinKZG10, LabeledPolynomial, PolynomialCommitment, QuerySet, Evaluations};
use ark_bls12_377::Bls12_377;
use ark_crypto_primitives::sponge::poseidon::{PoseidonSponge, PoseidonConfig};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::test_rng;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use rand_chacha::ChaCha20Rng;
use ark_ff::PrimeField;

type UniPoly_377 = DensePolynomial<<Bls12_377 as Pairing>::ScalarField>;
type PCS = MarlinKZG10<Bls12_377, UniPoly_377>;

let rng = &mut test_rng();

let max_degree = 16; // max degree supported by the scheme with the given public parameters generated by the setup here.

// 1. PolynomialCommitment::setup
// The setup procedure in this example is for demonstration purposes only - typically a setup ceremony would be run to generate the public parameters.
let pp = PCS::setup(max_degree, None, rng).unwrap();

let degree = 10; //degree of our polynomial
let secret_poly = UniPoly_377::rand(degree, rng);

let point_1 = <Bls12_377 as Pairing>::ScalarField::rand(rng);
let point_2 = <Bls12_377 as Pairing>::ScalarField::rand(rng);

let label = String::from("secret_poly");
let labeled_poly = LabeledPolynomial::new(
   label.clone(),
   secret_poly.clone(),
   Some(degree),
   Some(2), // we will open a univariate poly at two points
);

// TODO: replace by https://github.com/arkworks-rs/crypto-primitives/issues/112.
fn test_sponge<F: PrimeField>() -> PoseidonSponge<F> {
   let full_rounds = 8;
   let partial_rounds = 31;
   let alpha = 17;

   let mds = vec![
      vec![F::one(), F::zero(), F::one()],
      vec![F::one(), F::one(), F::zero()],
      vec![F::zero(), F::one(), F::one()],
   ];

   let mut v = Vec::new();
   let mut ark_rng = test_rng();

   for _ in 0..(full_rounds + partial_rounds) {
      let mut res = Vec::new();

      for _ in 0..3 {
         res.push(F::rand(&mut ark_rng));
      }
      v.push(res);
   }
   let config = PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, v, 2, 1);
   PoseidonSponge::new(&config)
}
let mut test_sponge = test_sponge::<<Bls12_377 as Pairing>::ScalarField>();

// 2. PolynomialCommitment::trim
// Since the setup produced pp with a max degree of 16, and our poly is of degree 10, we can trim the SRS to tailor it to this example.
let (ck, vk) = PCS::trim(&pp, degree, 2, Some(&[degree])).unwrap(); 

// 3. PolynomialCommitment::commit
// The prover commits to the polynomial using their committer key `ck`.
let (comms, states) = PCS::commit(&ck, [&labeled_poly], Some(rng)).unwrap(); 

// 4a. PolynomialCommitment::open
// Opening proof at a single point.
let proof_single = PCS::open(&ck, [&labeled_poly], &comms, &point_1, &mut (test_sponge.clone()), &states, None).unwrap(); 

// 5a. PolynomialCommitment::check
// Verifying the proof at a single point, given the commitment, the point, the claimed evaluation, and the proof.
assert!(PCS::check(&vk, &comms, &point_1, [secret_poly.evaluate(&point_1)], &proof_single, &mut (test_sponge.clone()), Some(rng)).unwrap()); 

let mut query_set = QuerySet::new();
let mut values = Evaluations::new();
for (i, point) in [point_1, point_2].iter().enumerate() {
   query_set.insert((label.clone(), (format!("{}", i), point.clone())));
   let value = secret_poly.evaluate(&point);
   values.insert((label.clone(), point.clone()), value);
}

// 4b. PolynomialCommitment::batch_open
// Some schemes support batch opening proofs. Generate a single proof for opening the polynomial at multiple points.
let proof_batched = PCS::batch_open(
   &ck,
   [&labeled_poly],
   &comms,
   &query_set,
   &mut (test_sponge.clone()),
   &states,
   Some(rng),
).unwrap();

// 5b. PolynomialCommitment::batch_check
assert!(PCS::batch_check(
   &vk,
   &comms,
   &query_set,
   &values,
   &proof_batched,
   &mut (test_sponge.clone()),
   rng,
).unwrap());
```

## License

This library is licensed under either of the following licenses, at your discretion.

 * [Apache License Version 2.0](LICENSE-APACHE)
 * [MIT License](LICENSE-MIT)

Unless you explicitly state otherwise, any contribution that you submit to this library shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.

[kzg10]: http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf
[marlin]: https://ia.cr/2019/1047
[sonic]: https://ia.cr/2019/099
[aurora-light]: https://ia.cr/2019/601
[pcd-acc]: https://ia.cr/2020/499
[pst]: https://ia.cr/2011/587
[brakedown]: https://ia.cr/2021/1043
[ligero]: https://ia.cr/2022/1608
[hyrax]: https://eprint.iacr.org/2017/1132

## Reference papers

[Polynomial Commitments][kzg10]     
Aniket Kate, Gregory M. Zaverucha, Ian Goldberg     
ASIACRYPT 2010

[Sonic: Zero-Knowledge SNARKs from Linear-Size Universal and Updateable Structured Reference Strings][sonic]     
Mary Maller, Sean Bowe, Markulf Kohlweiss, Sarah Meiklejohn     
CCS 2019

[AuroraLight: Improved Prover Efficiency and SRS Size in a Sonic-Like System][aurora-light]     
Ariel Gabizon     
ePrint, 2019

[Marlin: Preprocessing zkSNARKs with Universal and Updatable SRS][marlin]     
Alessandro Chiesa, Yuncong Hu, Mary Maller, [Pratyush Mishra](https://www.github.com/pratyush), Noah Vesely, [Nicholas Ward](https://www.github.com/npwardberkeley)     
EUROCRYPT 2020

[Proof-Carrying Data from Accumulation Schemes][pcd-acc]     
Benedikt Bünz, Alessandro Chiesa, [Pratyush Mishra](https://www.github.com/pratyush), Nicholas Spooner     
TCC 2020

[Signatures of Correct Computation][pst]    
Charalampos Papamanthou, Elaine Shi, Roberto Tamassia   
TCC 2013

[Ligero: Lightweight Sublinear Arguments Without a Trusted Setup][ligero]    
Scott Ames, Carmit Hazay, Yuval Ishai, Muthuramakrishnan Venkitasubramaniam    
CCS 2017

[Doubly-efficient zkSNARKs without trusted setup][hyrax]
Riad S. Wahby, Ioanna Tzialla, abhi shelat, Justin Thaler, Michael Walfish
2018 IEEE Symposium on Security and Privacy

[Brakedown: Linear-time and field-agnostic SNARKs for R1CS][brakedown]    
Alexander Golovnev, Jonathan Lee, Srinath Setty, Justin Thaler, Riad S. Wahby    
CRYPTO 2023

## Acknowledgements

This work was supported by: an Engineering and Physical Sciences Research Council grant; a Google Faculty Award; the RISELab at UC Berkeley; and donations from the Ethereum Foundation and the Interchain Foundation.
