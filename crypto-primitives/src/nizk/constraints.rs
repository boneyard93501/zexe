use algebra_core::Field;
use r1cs_core::SynthesisError;
use r1cs_std::prelude::*;

use crate::nizk::NIZK;

pub trait NIZKVerifierGadget<N: NIZK, ConstraintF: Field> {
    type PreparedVerificationKeyVar;
    type VerificationKeyVar: AllocVar<N::VerificationParameters, ConstraintF>
        + ToBytesGadget<ConstraintF>;
    type ProofVar: AllocVar<N::Proof, ConstraintF>;

    fn verify<'a, T: 'a + ToBitsGadget<ConstraintF> + ?Sized>(
        verification_key: &Self::VerificationKeyVar,
        input: impl Iterator<Item = &'a T>,
        proof: &Self::ProofVar,
    ) -> Result<(), SynthesisError> {
        Self::conditional_verify(verification_key, input, proof, &Boolean::constant(true))
    }

    fn conditional_verify<'a, T: 'a + ToBitsGadget<ConstraintF> + ?Sized>(
        verification_key: &Self::VerificationKeyVar,
        input: impl Iterator<Item = &'a T>,
        proof: &Self::ProofVar,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError>;

    fn conditional_verify_prepared<'a, T: 'a + ToBitsGadget<ConstraintF> + ?Sized>(
        prepared_verification_key: &Self::PreparedVerificationKeyVar,
        input: impl Iterator<Item = &'a T>,
        proof: &Self::ProofVar,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError>;
}
