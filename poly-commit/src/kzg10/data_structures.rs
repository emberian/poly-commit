use crate::*;
use ark_ec::{pairing::Pairing, AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::ToConstraintField;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use ark_std::{
    borrow::Cow,
    io::{Read, Write},
    marker::PhantomData,
    ops::{Add, AddAssign},
};

/// `UniversalParams` are the universal parameters for the KZG10 scheme.
#[derive(Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct UniversalParams<E: Pairing> {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_g: Vec<E::G1Affine>,
    /// Group elements of the form `{ \beta^i H }`, where `i` ranges from 0 to `degree`.
    pub powers_of_h: Vec<E::G2Affine>,
    /// Group elements of the form `{ \beta^i \gamma G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_gamma_g: BTreeMap<usize, E::G1Affine>,
    /// Group elements of the form `{ \beta^i H }`, where `i` ranges from 0 to `degree`.
    pub powers_of_gamma_h: BTreeMap<usize, E::G2Affine>,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
    /// Group elements of the form `{ \beta^i G2 }`, where `i` ranges from `0` to `-degree`.
    pub neg_powers_of_h: BTreeMap<usize, E::G2Affine>,
    /// The generator of G2, prepared for use in pairings.
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    pub prepared_h: E::G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    pub prepared_beta_h: E::G2Prepared,
}

impl<E: Pairing> Valid for UniversalParams<E> {
    fn check(&self) -> Result<(), SerializationError> {
        self.powers_of_g.check()?;
        self.powers_of_h.check()?;
        self.powers_of_gamma_g.check()?;
        self.powers_of_gamma_h.check()?;
        self.h.check()?;
        self.beta_h.check()?;
        self.neg_powers_of_h.check()?;
        Ok(())
    }
}
impl<E: Pairing> PCUniversalParams for UniversalParams<E> {
    fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }
}

impl<E: Pairing> CanonicalSerialize for UniversalParams<E> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.powers_of_g
            .serialize_with_mode(&mut writer, compress)?;
        self.powers_of_h
            .serialize_with_mode(&mut writer, compress)?;
        self.powers_of_gamma_g
            .serialize_with_mode(&mut writer, compress)?;
        self.powers_of_gamma_h
            .serialize_with_mode(&mut writer, compress)?;
        self.h.serialize_with_mode(&mut writer, compress)?;
        self.beta_h.serialize_with_mode(&mut writer, compress)?;
        self.neg_powers_of_h
            .serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.powers_of_g.serialized_size(compress)
            + self.powers_of_h.serialized_size(compress)
            + self.powers_of_gamma_g.serialized_size(compress)
            + self.powers_of_gamma_h.serialized_size(compress)
            + self.h.serialized_size(compress)
            + self.beta_h.serialized_size(compress)
            + self.neg_powers_of_h.serialized_size(compress)
    }
}

impl<E: Pairing> CanonicalDeserialize for UniversalParams<E> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let powers_of_g = Vec::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let powers_of_h = Vec::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let powers_of_gamma_g =
            BTreeMap::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let powers_of_gamma_h =
            BTreeMap::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let h = E::G2Affine::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let beta_h = E::G2Affine::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let neg_powers_of_h = BTreeMap::deserialize_with_mode(&mut reader, compress, Validate::No)?;

        let prepared_h = E::G2Prepared::from(h.clone());
        let prepared_beta_h = E::G2Prepared::from(beta_h.clone());
        let result = Self {
            powers_of_g,
            powers_of_h,
            powers_of_gamma_g,
            powers_of_gamma_h,
            h,
            beta_h,
            neg_powers_of_h,
            prepared_h,
            prepared_beta_h,
        };
        if let Validate::Yes = validate {
            result.check()?;
        }

        Ok(result)
    }
}

/// `Powers` is used to commit to and create evaluation proofs for a given
/// polynomial.
#[derive(Derivative)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq
)]
pub struct Powers<'a, E: Pairing> {
    /// Group elements of the form `β^i G`, for different values of `i`.
    pub powers_of_g: Cow<'a, [E::G1Affine]>,
    /// Group elements of the form `β^i γG`, for different values of `i`.
    pub powers_of_gamma_g: Cow<'a, [E::G1Affine]>,
    /// Group elements of the form `β^i H`, for different values of `i`.
    pub powers_of_h: Cow<'a, [E::G2Affine]>,
    /// Group elements of the form `β^i γH`, for different values of `i`.
    pub powers_of_gamma_h: Cow<'a, [E::G2Affine]>,
}

impl<E: Pairing> UniversalParams<E> {
    pub fn powers(&self) -> Powers<'_, E> {
        Powers {
            powers_of_g: Cow::Borrowed(&self.powers_of_g),
            powers_of_gamma_g: Cow::Owned(self.powers_of_gamma_g.values().cloned().collect()),
            powers_of_h: Cow::Borrowed(&self.powers_of_h),
            powers_of_gamma_h: Cow::Owned(self.powers_of_gamma_h.values().cloned().collect()),
        }
    }
}

impl<E: Pairing> Powers<'_, E> {
    /// The number of powers in `self`.
    pub fn size(&self) -> usize {
        self.powers_of_g.len()
    }
}
impl<'a, E: Pairing> Valid for Powers<'a, E> {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
impl<'a, E: Pairing> CanonicalSerialize for Powers<'a, E> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.powers_of_g
            .serialize_with_mode(&mut writer, compress)?;
        self.powers_of_gamma_g
            .serialize_with_mode(&mut writer, compress)?;
        self.powers_of_h
            .serialize_with_mode(&mut writer, compress)?;
        self.powers_of_gamma_h
            .serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.powers_of_g.serialized_size(compress)
            + self.powers_of_gamma_g.serialized_size(compress)
            + self.powers_of_h.serialized_size(compress)
            + self.powers_of_gamma_h.serialized_size(compress)
    }
}

impl<'a, E: Pairing> CanonicalDeserialize for Powers<'a, E> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let powers_of_g = Vec::deserialize_with_mode(&mut reader, compress, validate)?;
        let powers_of_gamma_g = Vec::deserialize_with_mode(&mut reader, compress, validate)?;
        let powers_of_h = Vec::deserialize_with_mode(&mut reader, compress, validate)?;
        let powers_of_gamma_h = Vec::deserialize_with_mode(&mut reader, compress, validate)?;
        let result = Self {
            powers_of_g: Cow::Owned(powers_of_g),
            powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
            powers_of_h: Cow::Owned(powers_of_h),
            powers_of_gamma_h: Cow::Owned(powers_of_gamma_h),
        };
        if let Validate::Yes = validate {
            result.check()?;
        }
        Ok(result)
    }
}
/// `VerifierKey` is used to check evaluation proofs for a given commitment.
#[derive(Derivative)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct VerifierKey<E: Pairing> {
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G1 that is used for making a commitment hiding.
    pub gamma_g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// The generator of G2 that is used for making a commitment hiding.
    pub gamma_h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
    /// The generator of G2, prepared for use in pairings.
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    pub prepared_h: E::G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    pub prepared_beta_h: E::G2Prepared,
}

impl<E: Pairing> UniversalParams<E> {
    pub fn vk(&self) -> VerifierKey<E> {
        VerifierKey {
            g: self.powers_of_g[0],
            gamma_g: self.powers_of_gamma_g[&0],
            h: self.h,
            gamma_h: self.powers_of_gamma_h[&0],
            beta_h: self.beta_h,
            prepared_h: self.prepared_h.clone(),
            prepared_beta_h: self.prepared_beta_h.clone(),
        }
    }
}

impl<E: Pairing> Valid for VerifierKey<E> {
    fn check(&self) -> Result<(), SerializationError> {
        self.g.check()?;
        self.gamma_g.check()?;
        self.h.check()?;
        self.gamma_h.check()?;
        self.beta_h.check()?;

        Ok(())
    }
}

impl<E: Pairing> CanonicalSerialize for VerifierKey<E> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.g.serialize_with_mode(&mut writer, compress)?;
        self.gamma_g.serialize_with_mode(&mut writer, compress)?;
        self.h.serialize_with_mode(&mut writer, compress)?;
        self.gamma_h.serialize_with_mode(&mut writer, compress)?;
        self.beta_h.serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.g.serialized_size(compress)
            + self.gamma_g.serialized_size(compress)
            + self.h.serialized_size(compress)
            + self.gamma_h.serialized_size(compress)
            + self.beta_h.serialized_size(compress)
    }
}

impl<E: Pairing> CanonicalDeserialize for VerifierKey<E> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let g = E::G1Affine::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let gamma_g = E::G1Affine::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let h = E::G2Affine::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let gamma_h = E::G2Affine::deserialize_with_mode(&mut reader, compress, Validate::No)?;
        let beta_h = E::G2Affine::deserialize_with_mode(&mut reader, compress, Validate::No)?;

        let prepared_h = E::G2Prepared::from(h.clone());
        let prepared_beta_h = E::G2Prepared::from(beta_h.clone());
        let result = Self {
            g,
            gamma_g,
            h,
            gamma_h,
            beta_h,
            prepared_h,
            prepared_beta_h,
        };
        if let Validate::Yes = validate {
            result.check()?;
        }

        Ok(result)
    }
}

impl<E: Pairing> ToConstraintField<<E::TargetField as Field>::BasePrimeField> for VerifierKey<E>
where
    E::G1Affine: ToConstraintField<<E::TargetField as Field>::BasePrimeField>,
    E::G2Affine: ToConstraintField<<E::TargetField as Field>::BasePrimeField>,
{
    fn to_field_elements(&self) -> Option<Vec<<E::TargetField as Field>::BasePrimeField>> {
        let mut res = Vec::new();

        res.extend_from_slice(&self.g.to_field_elements().unwrap());
        res.extend_from_slice(&self.gamma_g.to_field_elements().unwrap());
        res.extend_from_slice(&self.h.to_field_elements().unwrap());
        res.extend_from_slice(&self.gamma_h.to_field_elements().unwrap());
        res.extend_from_slice(&self.beta_h.to_field_elements().unwrap());

        Some(res)
    }
}

/// `PreparedVerifierKey` is the fully prepared version for checking evaluation proofs for a given commitment.
/// We omit gamma here for simplicity.
#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Debug(bound = ""))]
pub struct PreparedVerifierKey<E: Pairing> {
    /// The generator of G1, prepared for power series.
    pub prepared_g: Vec<E::G1Affine>,
    /// The generator of G2, prepared for use in pairings.
    pub prepared_h: E::G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    pub prepared_beta_h: E::G2Prepared,
}

impl<E: Pairing> PreparedVerifierKey<E> {
    /// prepare `PreparedVerifierKey` from `VerifierKey`
    pub fn prepare(vk: &VerifierKey<E>) -> Self {
        let supported_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;

        let mut prepared_g = Vec::<E::G1Affine>::new();
        let mut g = E::G1::from(vk.g.clone());
        for _ in 0..supported_bits {
            prepared_g.push(g.clone().into());
            g.double_in_place();
        }

        Self {
            prepared_g,
            prepared_h: vk.prepared_h.clone(),
            prepared_beta_h: vk.prepared_beta_h.clone(),
        }
    }
}

/// Macro to implement commitment types and their associated functionality
macro_rules! commitment_impl {
    ($commitment_type:ident, $prepared_commitment_type:ident, $group_type:ty) => {
        /// `$commitment_type` commits to a polynomial. It is output by `KZG10::commit`.
        #[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
        #[derivative(
            Default(bound = ""),
            Hash(bound = ""),
            Clone(bound = ""),
            Copy(bound = ""),
            Debug(bound = ""),
            PartialEq(bound = ""),
            Eq(bound = "")
        )]
        pub struct $commitment_type<E: Pairing>(
            /// The commitment is a group element.
            pub $group_type,
        );

        impl<E: Pairing> $commitment_type<E> {
            pub fn map(&self, f: impl Fn($group_type) -> $group_type) -> Self {
                $commitment_type(f(self.0))
            }

            pub fn combine<'a, I: IntoIterator<Item = &'a $commitment_type<E>>>(
                comms: I,
                r: E::ScalarField,
            ) -> Self {
                let mut comm = <$group_type as AffineRepr>::Group::ZERO;
                for (i, c) in comms.into_iter().enumerate() {
                    comm += c.0 * r.pow([i as u64]);
                }
                $commitment_type(comm.into_affine())
            }
        }

        impl<E: Pairing> PCCommitment for $commitment_type<E> {
            #[inline]
            fn empty() -> Self {
                $commitment_type(<$group_type>::zero())
            }

            fn has_degree_bound(&self) -> bool {
                false
            }
        }

        impl<E: Pairing> ToConstraintField<<E::TargetField as Field>::BasePrimeField>
            for $commitment_type<E>
        where
            $group_type: ToConstraintField<<E::TargetField as Field>::BasePrimeField>,
        {
            fn to_field_elements(&self) -> Option<Vec<<E::TargetField as Field>::BasePrimeField>> {
                self.0.to_field_elements()
            }
        }

        impl<'a, E: Pairing> AddAssign<(E::ScalarField, &'a $commitment_type<E>)>
            for $commitment_type<E>
        {
            #[inline]
            fn add_assign(&mut self, (f, other): (E::ScalarField, &'a $commitment_type<E>)) {
                let mut other = other.0 * f;
                other.add_assign(&self.0);
                self.0 = other.into();
            }
        }

        /// `$prepared_commitment_type` commits to a polynomial and prepares for mul_bits.
        #[derive(Derivative)]
        #[derivative(
            Default(bound = ""),
            Hash(bound = ""),
            Clone(bound = ""),
            Debug(bound = ""),
            PartialEq(bound = ""),
            Eq(bound = "")
        )]
        pub struct $prepared_commitment_type<E: Pairing>(
            /// The commitment is a group element.
            pub Vec<$group_type>,
        );

        impl<E: Pairing> $prepared_commitment_type<E> {
            /// prepare `$prepared_commitment_type` from `$commitment_type`
            pub fn prepare(comm: &$commitment_type<E>) -> Self {
                let mut prepared_comm = Vec::<$group_type>::new();
                let mut cur = <$group_type as AffineRepr>::Group::from(comm.0.clone());

                let supported_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;

                for _ in 0..supported_bits {
                    prepared_comm.push(cur.clone().into());
                    cur.double_in_place();
                }

                Self { 0: prepared_comm }
            }
        }
    };
}

// Use the macro to implement CommitmentG1 (previously Commitment) and CommitmentG2
commitment_impl!(CommitmentG1, PreparedCommitmentG1, E::G1Affine);
commitment_impl!(CommitmentG2, PreparedCommitmentG2, E::G2Affine);

// For backward compatibility
/// Alias for CommitmentG1 to maintain backward compatibility
pub type Commitment<E> = CommitmentG1<E>;

/// Alias for PreparedCommitmentG1 to maintain backward compatibility
pub type PreparedCommitment<E> = PreparedCommitmentG1<E>;

/// `Randomness` hides the polynomial inside a commitment. It is output by `KZG10::commit`.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Hash(bound = ""),
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct Randomness<F: PrimeField, P: DenseUVPolynomial<F>> {
    /// For KZG10, the commitment randomness is a random polynomial.
    pub blinding_polynomial: P,
    _field: PhantomData<F>,
}

impl<F: PrimeField, P: DenseUVPolynomial<F>> Randomness<F, P> {
    /// Does `self` provide any hiding properties to the corresponding commitment?
    /// `self.is_hiding() == true` only if the underlying polynomial is non-zero.
    #[inline]
    pub fn is_hiding(&self) -> bool {
        !self.blinding_polynomial.is_zero()
    }

    /// What is the degree of the hiding polynomial for a given hiding bound?
    #[inline]
    pub fn calculate_hiding_polynomial_degree(hiding_bound: usize) -> usize {
        hiding_bound + 1
    }
}

impl<F: PrimeField, P: DenseUVPolynomial<F>> PCCommitmentState for Randomness<F, P> {
    type Randomness = Self;
    fn empty() -> Self {
        Self {
            blinding_polynomial: P::zero(),
            _field: PhantomData,
        }
    }

    fn rand<R: RngCore>(hiding_bound: usize, _: bool, _: Option<usize>, rng: &mut R) -> Self {
        let mut randomness = Randomness::empty();
        let hiding_poly_degree = Self::calculate_hiding_polynomial_degree(hiding_bound);
        randomness.blinding_polynomial = P::rand(hiding_poly_degree, rng);
        randomness
    }
}

impl<'a, F: PrimeField, P: DenseUVPolynomial<F>> Add<&'a Randomness<F, P>> for Randomness<F, P> {
    type Output = Self;

    #[inline]
    fn add(mut self, other: &'a Self) -> Self {
        self.blinding_polynomial += &other.blinding_polynomial;
        self
    }
}

impl<'a, F: PrimeField, P: DenseUVPolynomial<F>> Add<(F, &'a Randomness<F, P>)>
    for Randomness<F, P>
{
    type Output = Self;

    #[inline]
    fn add(mut self, other: (F, &'a Randomness<F, P>)) -> Self {
        self += other;
        self
    }
}

impl<'a, F: PrimeField, P: DenseUVPolynomial<F>> AddAssign<&'a Randomness<F, P>>
    for Randomness<F, P>
{
    #[inline]
    fn add_assign(&mut self, other: &'a Self) {
        self.blinding_polynomial += &other.blinding_polynomial;
    }
}

impl<'a, F: PrimeField, P: DenseUVPolynomial<F>> AddAssign<(F, &'a Randomness<F, P>)>
    for Randomness<F, P>
{
    #[inline]
    fn add_assign(&mut self, (f, other): (F, &'a Randomness<F, P>)) {
        self.blinding_polynomial += (f, &other.blinding_polynomial);
    }
}

/// `Proof` is an evaluation proof that is output by `KZG10::open`.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct Proof<E: Pairing> {
    /// This is a commitment to the witness polynomial; see [KZG10] for more details.
    pub w: E::G1Affine,
    /// This is the evaluation of the random polynomial at the point for which
    /// the evaluation proof was produced.
    pub random_v: Option<E::ScalarField>,
}

impl<E: Pairing> Proof<E> {
    /// Combine many openings evaluated at the same point into a single proof.
    pub fn combine<'a, I: IntoIterator<Item = &'a Proof<E>>>(proofs: I, r: E::ScalarField) -> Self {
        let mut w = E::G1::ZERO;
        let mut random_v = None;
        for (i, proof) in proofs.into_iter().enumerate() {
            w += proof.w * r.pow([i as u64]);
            match &proof.random_v {
                Some(v) => {
                    if random_v.is_none() {
                        random_v = Some(E::ScalarField::ZERO);
                    }
                    random_v = random_v.map(|rv| rv + v);
                }
                None => {}
            }
        }
        Proof {
            w: w.into_affine(),
            random_v,
        }
    }
}
