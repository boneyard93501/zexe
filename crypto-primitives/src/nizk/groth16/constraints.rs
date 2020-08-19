use crate::{
    nizk::{groth16::Groth16, NIZKVerifierGadget},
    Vec,
};
use algebra_core::{PairingEngine, ToConstraintField};
use r1cs_core::{ConstraintSynthesizer, Namespace, SynthesisError};
use r1cs_std::prelude::*;

use core::{borrow::Borrow, marker::PhantomData};
use groth16::{PreparedVerifyingKey, Proof, VerifyingKey};

#[derive(Derivative)]
#[derivative(Clone(bound = "P::G1Var: Clone, P::G2Var: Clone"))]
pub struct ProofVar<E: PairingEngine, P: PairingVar<E>>
where
    for<'a> &'a P::G1Var: GroupOpsBounds<'a, E::G1Projective, P::G1Var>,
    for<'a> &'a P::G2Var: GroupOpsBounds<'a, E::G2Projective, P::G2Var>,
    for<'a> &'a P::GTVar: FieldOpsBounds<'a, E::Fqk, P::GTVar>,
{
    pub a: P::G1Var,
    pub b: P::G2Var,
    pub c: P::G1Var,
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "P::G1Var: Clone, P::GTVar: Clone, P::G1PreparedVar: Clone, \
             P::G2PreparedVar: Clone, ")
)]
pub struct VerifyingKeyVar<E: PairingEngine, P: PairingVar<E>>
where
    for<'a> &'a P::G1Var: GroupOpsBounds<'a, E::G1Projective, P::G1Var>,
    for<'a> &'a P::G2Var: GroupOpsBounds<'a, E::G2Projective, P::G2Var>,
    for<'a> &'a P::GTVar: FieldOpsBounds<'a, E::Fqk, P::GTVar>,
{
    pub alpha_g1: P::G1Var,
    pub beta_g2: P::G2Var,
    pub gamma_g2: P::G2Var,
    pub delta_g2: P::G2Var,
    pub gamma_abc_g1: Vec<P::G1Var>,
}

impl<E: PairingEngine, P: PairingVar<E>> VerifyingKeyVar<E, P>
where
    for<'a> &'a P::G1Var: GroupOpsBounds<'a, E::G1Projective, P::G1Var>,
    for<'a> &'a P::G2Var: GroupOpsBounds<'a, E::G2Projective, P::G2Var>,
    for<'a> &'a P::GTVar: FieldOpsBounds<'a, E::Fqk, P::GTVar>,
{
    pub fn prepare(&self) -> Result<PreparedVerifyingKeyVar<E, P>, SynthesisError> {
        let alpha_g1_pc = P::prepare_g1(&self.alpha_g1)?;
        let beta_g2_pc = P::prepare_g2(&self.beta_g2)?;

        let alpha_g1_beta_g2 = P::pairing(alpha_g1_pc, beta_g2_pc)?;
        let gamma_g2_neg_pc = P::prepare_g2(&self.gamma_g2.negate()?)?;
        let delta_g2_neg_pc = P::prepare_g2(&self.delta_g2.negate()?)?;

        Ok(PreparedVerifyingKeyVar {
            alpha_g1_beta_g2,
            gamma_g2_neg_pc,
            delta_g2_neg_pc,
            gamma_abc_g1: self.gamma_abc_g1.clone(),
        })
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "P::G1Var: Clone, P::GTVar: Clone, P::G1PreparedVar: Clone, \
             P::G2PreparedVar: Clone, ")
)]
pub struct PreparedVerifyingKeyVar<E: PairingEngine, P: PairingVar<E>>
where
    for<'a> &'a P::G1Var: GroupOpsBounds<'a, E::G1Projective, P::G1Var>,
    for<'a> &'a P::G2Var: GroupOpsBounds<'a, E::G2Projective, P::G2Var>,
    for<'a> &'a P::GTVar: FieldOpsBounds<'a, E::Fqk, P::GTVar>,
{
    pub alpha_g1_beta_g2: P::GTVar,
    pub gamma_g2_neg_pc: P::G2PreparedVar,
    pub delta_g2_neg_pc: P::G2PreparedVar,
    pub gamma_abc_g1: Vec<P::G1Var>,
}

pub struct Groth16VerifierGadget<E, P>
where
    E: PairingEngine,

    P: PairingVar<E>,
    for<'a> &'a P::G1Var: GroupOpsBounds<'a, E::G1Projective, P::G1Var>,
    for<'a> &'a P::G2Var: GroupOpsBounds<'a, E::G2Projective, P::G2Var>,
    for<'a> &'a P::GTVar: FieldOpsBounds<'a, E::Fqk, P::GTVar>,
{
    _pairing_engine: PhantomData<E>,
    _pairing_gadget: PhantomData<P>,
}

impl<E, P, C, V> NIZKVerifierGadget<Groth16<E, C, V>, P::ConstraintF>
    for Groth16VerifierGadget<E, P>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    V: ToConstraintField<E::Fr>,
    P: PairingVar<E>,
    for<'a> &'a P::G1Var: GroupOpsBounds<'a, E::G1Projective, P::G1Var>,
    for<'a> &'a P::G2Var: GroupOpsBounds<'a, E::G2Projective, P::G2Var>,
    for<'a> &'a P::GTVar: FieldOpsBounds<'a, E::Fqk, P::GTVar>,
{
    type PreparedVerificationKeyVar = PreparedVerifyingKeyVar<E, P>;
    type VerificationKeyVar = VerifyingKeyVar<E, P>;
    type ProofVar = ProofVar<E, P>;

    fn conditional_verify<'a, T: 'a + ToBitsGadget<P::ConstraintF> + ?Sized>(
        vk: &Self::VerificationKeyVar,
        input: impl Iterator<Item = &'a T>,
        proof: &Self::ProofVar,
        condition: &Boolean<P::ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let pvk = vk.prepare()?;
        <Self as NIZKVerifierGadget<Groth16<E, C, V>, P::ConstraintF>>::conditional_verify_prepared(
            &pvk, input, proof, condition,
        )
    }

    fn conditional_verify_prepared<'a, T: 'a + ToBitsGadget<P::ConstraintF> + ?Sized>(
        pvk: &Self::PreparedVerificationKeyVar,
        mut public_inputs: impl Iterator<Item = &'a T>,
        proof: &Self::ProofVar,
        condition: &Boolean<P::ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let pvk = pvk.clone();

        let g_ic = {
            let mut g_ic: P::G1Var = pvk.gamma_abc_g1[0].clone();
            let mut input_len = 1;
            for (input, b) in public_inputs.by_ref().zip(pvk.gamma_abc_g1.iter().skip(1)) {
                let encoded_input_i: P::G1Var = b.mul_bits(input.to_bits()?.iter())?;
                g_ic += encoded_input_i;
                input_len += 1;
            }
            // Check that the input and the query in the verification are of the
            // same length.
            assert!(input_len == pvk.gamma_abc_g1.len() && public_inputs.next().is_none());
            g_ic
        };

        let test_exp = {
            let proof_a_prep = P::prepare_g1(&proof.a)?;
            let proof_b_prep = P::prepare_g2(&proof.b)?;
            let proof_c_prep = P::prepare_g1(&proof.c)?;

            let g_ic_prep = P::prepare_g1(&g_ic)?;

            P::miller_loop(
                &[proof_a_prep, g_ic_prep, proof_c_prep],
                &[
                    proof_b_prep,
                    pvk.gamma_g2_neg_pc.clone(),
                    pvk.delta_g2_neg_pc.clone(),
                ],
            )?
        };

        let test = P::final_exponentiation(&test_exp).unwrap();

        test.conditional_enforce_equal(&pvk.alpha_g1_beta_g2, condition)?;
        Ok(())
    }
}

impl<E, P> AllocVar<PreparedVerifyingKey<E>, P::ConstraintF> for PreparedVerifyingKeyVar<E, P>
where
    E: PairingEngine,
    P: PairingVar<E>,
    for<'a> &'a P::G1Var: GroupOpsBounds<'a, E::G1Projective, P::G1Var>,
    for<'a> &'a P::G2Var: GroupOpsBounds<'a, E::G2Projective, P::G2Var>,
    for<'a> &'a P::GTVar: FieldOpsBounds<'a, E::Fqk, P::GTVar>,
{
    fn new_variable<T: Borrow<PreparedVerifyingKey<E>>>(
        cs: impl Into<Namespace<P::ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|pvk| {
            let pvk = pvk.borrow();
            let alpha_g1_beta_g2 = P::GTVar::new_variable(
                cs.ns("alpha_g1_beta_g2"),
                || Ok(pvk.alpha_g1_beta_g2),
                mode,
            )?;

            let gamma_g2_neg_pc = P::G2PreparedVar::new_variable(
                cs.ns("gamma_g2_neg_pc"),
                || Ok(pvk.gamma_g2_neg_pc.clone()),
                mode,
            )?;

            let delta_g2_neg_pc = P::G2PreparedVar::new_variable(
                cs.ns("delta_g2_neg_pc"),
                || Ok(pvk.delta_g2_neg_pc.clone()),
                mode,
            )?;

            let gamma_abc_g1 =
                Vec::new_variable(cs.ns("gamma_abc_g1"), || Ok(pvk.gamma_abc_g1.clone()), mode)?;

            Ok(Self {
                alpha_g1_beta_g2,
                gamma_g2_neg_pc,
                delta_g2_neg_pc,
                gamma_abc_g1,
            })
        })
    }
}

impl<E, P> AllocVar<VerifyingKey<E>, P::ConstraintF> for VerifyingKeyVar<E, P>
where
    E: PairingEngine,

    P: PairingVar<E>,
    for<'a> &'a P::G1Var: GroupOpsBounds<'a, E::G1Projective, P::G1Var>,
    for<'a> &'a P::G2Var: GroupOpsBounds<'a, E::G2Projective, P::G2Var>,
    for<'a> &'a P::GTVar: FieldOpsBounds<'a, E::Fqk, P::GTVar>,
{
    fn new_variable<T: Borrow<VerifyingKey<E>>>(
        cs: impl Into<Namespace<P::ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|vk| {
            let VerifyingKey {
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                gamma_abc_g1,
            } = vk.borrow().clone();
            let alpha_g1 = P::G1Var::new_variable(cs.ns("alpha_g1"), || Ok(alpha_g1), mode)?;
            let beta_g2 = P::G2Var::new_variable(cs.ns("beta_g2"), || Ok(beta_g2), mode)?;
            let gamma_g2 = P::G2Var::new_variable(cs.ns("gamma_g2"), || Ok(gamma_g2), mode)?;
            let delta_g2 = P::G2Var::new_variable(cs.ns("delta_g2"), || Ok(delta_g2), mode)?;

            let gamma_abc_g1 = Vec::new_variable(cs.clone(), || Ok(gamma_abc_g1), mode)?;
            Ok(Self {
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                gamma_abc_g1,
            })
        })
    }
}

impl<E, P> AllocVar<Proof<E>, P::ConstraintF> for ProofVar<E, P>
where
    E: PairingEngine,
    P: PairingVar<E>,
    for<'a> &'a P::G1Var: GroupOpsBounds<'a, E::G1Projective, P::G1Var>,
    for<'a> &'a P::G2Var: GroupOpsBounds<'a, E::G2Projective, P::G2Var>,
    for<'a> &'a P::GTVar: FieldOpsBounds<'a, E::Fqk, P::GTVar>,
{
    fn new_variable<T: Borrow<Proof<E>>>(
        cs: impl Into<Namespace<P::ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|proof| {
            let Proof { a, b, c } = proof.borrow().clone();
            let a = P::G1Var::new_variable(cs.ns("a"), || Ok(a), mode)?;
            let b = P::G2Var::new_variable(cs.ns("b"), || Ok(b), mode)?;
            let c = P::G1Var::new_variable(cs.ns("c"), || Ok(c), mode)?;
            Ok(Self { a, b, c })
        })
    }
}

impl<E, P> ToBytesGadget<P::ConstraintF> for VerifyingKeyVar<E, P>
where
    E: PairingEngine,
    P: PairingVar<E>,
    for<'a> &'a P::G1Var: GroupOpsBounds<'a, E::G1Projective, P::G1Var>,
    for<'a> &'a P::G2Var: GroupOpsBounds<'a, E::G2Projective, P::G2Var>,
    for<'a> &'a P::GTVar: FieldOpsBounds<'a, E::Fqk, P::GTVar>,
{
    #[inline]
    fn to_bytes(&self) -> Result<Vec<UInt8<P::ConstraintF>>, SynthesisError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.alpha_g1.to_bytes()?);
        bytes.extend_from_slice(&self.beta_g2.to_bytes()?);
        bytes.extend_from_slice(&self.gamma_g2.to_bytes()?);
        bytes.extend_from_slice(&self.delta_g2.to_bytes()?);
        for g in &self.gamma_abc_g1 {
            bytes.extend_from_slice(&g.to_bytes()?);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use groth16::*;
    use r1cs_core::{
        lc, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
    };

    use super::*;
    use algebra::{
        bls12_377::{Bls12_377, Fq, Fr},
        test_rng, BitIterator, Field, PrimeField,
    };
    use r1cs_std::{bls12_377::PairingVar as Bls12_377PairingVar, boolean::Boolean, Assignment};
    use rand::Rng;

    type TestProofSystem = Groth16<Bls12_377, Bench<Fr>, Fr>;
    type TestVerifierGadget = Groth16VerifierGadget<Bls12_377, Bls12_377PairingVar>;
    type TestProofVar = ProofVar<Bls12_377, Bls12_377PairingVar>;
    type TestVkVar = VerifyingKeyVar<Bls12_377, Bls12_377PairingVar>;

    struct Bench<F: Field> {
        inputs: Vec<Option<F>>,
        num_constraints: usize,
    }

    impl<F: Field> ConstraintSynthesizer<F> for Bench<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            assert!(self.inputs.len() >= 2);
            assert!(self.num_constraints >= self.inputs.len());

            let mut variables: Vec<_> = Vec::with_capacity(self.inputs.len());
            for input in self.inputs {
                let input_var = cs.new_input_variable(|| input.get())?;
                variables.push((input, input_var));
            }

            for i in 0..self.num_constraints {
                let new_entry = {
                    let (input_1_val, input_1_var) = variables[i];
                    let (input_2_val, input_2_var) = variables[i + 1];
                    let result_val = input_1_val
                        .and_then(|input_1| input_2_val.map(|input_2| input_1 * &input_2));
                    let result_var = cs.new_witness_variable(|| {
                        result_val.ok_or(SynthesisError::AssignmentMissing)
                    })?;
                    cs.enforce_named_constraint(
                        format!("Enforce constraint {}", i),
                        lc!() + input_1_var,
                        lc!() + input_2_var,
                        lc!() + result_var,
                    )
                    .unwrap();
                    (result_val, result_var)
                };
                variables.push(new_entry);
            }
            Ok(())
        }
    }

    #[test]
    fn groth16_verifier_test() {
        let num_inputs = 100;
        let num_constraints = num_inputs;
        let rng = &mut test_rng();
        let mut inputs: Vec<Option<Fr>> = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            inputs.push(Some(rng.gen()));
        }
        let params = {
            let c = Bench::<Fr> {
                inputs: vec![None; num_inputs],
                num_constraints,
            };

            generate_random_parameters(c, rng).unwrap()
        };

        {
            let proof = {
                // Create an instance of our circuit (with the
                // witness)
                let c = Bench {
                    inputs: inputs.clone(),
                    num_constraints,
                };
                // Create a groth16 proof with our parameters.
                create_random_proof(c, &params, rng).unwrap()
            };

            // assert!(!verify_proof(&pvk, &proof, &[a]).unwrap());
            let cs = ConstraintSystem::<Fq>::new_ref();

            let inputs: Vec<_> = inputs.into_iter().map(|input| input.unwrap()).collect();
            let mut input_gadgets = Vec::new();

            {
                for (i, input) in inputs.into_iter().enumerate() {
                    let mut input_bits = BitIterator::new(input.into_repr()).collect::<Vec<_>>();
                    // Input must be in little-endian, but BitIterator outputs in big-endian.
                    input_bits.reverse();

                    let input_bits =
                        Vec::<Boolean<Fq>>::new_input(cs.ns(format!("Input {}", i)), || {
                            Ok(input_bits)
                        })
                        .unwrap();
                    input_gadgets.push(input_bits);
                }
            }

            let vk_gadget = TestVkVar::new_input(cs.ns("Vk"), || Ok(&params.vk)).unwrap();
            let proof_gadget =
                TestProofVar::new_witness(cs.ns("Proof"), || Ok(proof.clone())).unwrap();
            println!("Time to verify!\n\n\n\n");
            <TestVerifierGadget as NIZKVerifierGadget<TestProofSystem, Fq>>::verify(
                &vk_gadget,
                input_gadgets.iter(),
                &proof_gadget,
            )
            .unwrap();
            if !cs.is_satisfied().unwrap() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{:?}", cs.which_is_unsatisfied().unwrap());
                println!("=========================================================");
            }

            // cs.print_named_objects();
            assert!(cs.is_satisfied().unwrap());
        }
    }
}

#[cfg(test)]
mod test_recursive {
    use groth16::*;
    use r1cs_core::{
        lc, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
    };

    use super::*;
    use algebra::{
        fields::{FftParameters, FpParameters},
        mnt4_298::{Fq as MNT4Fq, FqParameters as MNT4FqParameters, Fr as MNT4Fr, MNT4_298},
        mnt6_298::{Fq as MNT6Fq, FqParameters as MNT6FqParameters, Fr as MNT6Fr, MNT6_298},
        test_rng, BigInteger, Field, PrimeField,
    };
    use r1cs_std::{
        fields::fp::FpVar, mnt4_298::PairingVar as MNT4_298PairingVar,
        mnt6_298::PairingVar as MNT6_298PairingVar, uint8::UInt8, Assignment,
    };
    use rand::Rng;

    type TestProofSystem1 = Groth16<MNT6_298, Bench<MNT4Fq>, MNT6Fr>;
    type TestVerifierGadget1 = Groth16VerifierGadget<MNT6_298, MNT6_298PairingVar>;
    type TestProofVar1 = ProofVar<MNT6_298, MNT6_298PairingVar>;
    type TestVkVar1 = VerifyingKeyVar<MNT6_298, MNT6_298PairingVar>;

    type TestProofSystem2 = Groth16<MNT4_298, Wrapper, MNT4Fr>;
    type TestVerifierGadget2 = Groth16VerifierGadget<MNT4_298, MNT4_298PairingVar>;
    type TestProofVar2 = ProofVar<MNT4_298, MNT4_298PairingVar>;
    type TestVkVar2 = VerifyingKeyVar<MNT4_298, MNT4_298PairingVar>;

    #[derive(Clone)]
    struct Bench<F: Field> {
        inputs: Vec<Option<F>>,
        num_constraints: usize,
    }

    impl<F: Field> ConstraintSynthesizer<F> for Bench<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            assert!(self.inputs.len() >= 2);
            assert!(self.num_constraints >= self.inputs.len());

            let mut variables: Vec<_> = Vec::with_capacity(self.inputs.len());
            for input in self.inputs {
                let input_var = cs.new_input_variable(|| input.get())?;
                variables.push((input, input_var));
            }

            for i in 0..self.num_constraints {
                let new_entry = {
                    let (input_1_val, input_1_var) = variables[i];
                    let (input_2_val, input_2_var) = variables[i + 1];
                    let result_val = input_1_val
                        .and_then(|input_1| input_2_val.map(|input_2| input_1 * &input_2));
                    let result_var = cs.new_witness_variable(|| {
                        result_val.ok_or(SynthesisError::AssignmentMissing)
                    })?;
                    cs.enforce_named_constraint(
                        format!("Enforce constraint {}", i),
                        lc!() + input_1_var,
                        lc!() + input_2_var,
                        lc!() + result_var,
                    )
                    .unwrap();
                    (result_val, result_var)
                };
                variables.push(new_entry);
            }
            Ok(())
        }
    }

    struct Wrapper {
        inputs: Vec<Option<MNT4Fq>>,
        params: Parameters<MNT6_298>,
        proof: Proof<MNT6_298>,
    }

    impl ConstraintSynthesizer<MNT6Fq> for Wrapper {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<MNT6Fq>,
        ) -> Result<(), SynthesisError> {
            let params = self.params;
            let proof = self.proof;
            let inputs: Vec<_> = self
                .inputs
                .into_iter()
                .map(|input| input.unwrap())
                .collect();
            let input_gadgets;

            {
                // Chain all input values in one large byte array.
                let input_bytes = inputs
                    .clone()
                    .into_iter()
                    .flat_map(|input| {
                        input
                            .into_repr()
                            .as_ref()
                            .iter()
                            .flat_map(|l| l.to_le_bytes().to_vec())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                // Allocate this byte array as input packed into field elements.
                let input_bytes = UInt8::new_input_vec(cs.ns("Input"), &input_bytes[..])?;
                // 40 byte
                let element_size = <MNT4FqParameters as FftParameters>::BigInt::NUM_LIMBS * 8;
                input_gadgets = input_bytes
                    .chunks(element_size)
                    .map(|chunk| {
                        chunk
                            .iter()
                            .flat_map(|byte| byte.into_bits_le())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
            }

            let vk_gadget = TestVkVar1::new_witness(cs.ns("Vk"), || Ok(&params.vk))?;
            let proof_gadget =
                TestProofVar1::new_witness(cs.ns("Proof"), || Ok(proof.clone())).unwrap();
            <TestVerifierGadget1 as NIZKVerifierGadget<TestProofSystem1, MNT6Fq>>::verify(
                &vk_gadget,
                input_gadgets.iter(),
                &proof_gadget,
            )?;
            Ok(())
        }
    }

    #[test]
    fn groth16_recursive_verifier_test() {
        let num_inputs = 5;
        let num_constraints = num_inputs;
        let rng = &mut test_rng();
        let mut inputs: Vec<Option<MNT4Fq>> = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            inputs.push(Some(rng.gen()));
        }

        // Generate inner params and proof.
        let inner_params = {
            let c = Bench::<MNT4Fq> {
                inputs: vec![None; num_inputs],
                num_constraints,
            };

            generate_random_parameters(c, rng).unwrap()
        };

        let inner_proof = {
            // Create an instance of our circuit (with the
            // witness)
            let c = Bench {
                inputs: inputs.clone(),
                num_constraints,
            };
            // Create a groth16 proof with our parameters.
            create_random_proof(c, &inner_params, rng).unwrap()
        };

        // Generate outer params and proof.
        let params = {
            let c = Wrapper {
                inputs: inputs.clone(),
                params: inner_params.clone(),
                proof: inner_proof.clone(),
            };

            generate_random_parameters(c, rng).unwrap()
        };

        {
            let proof = {
                // Create an instance of our circuit (with the
                // witness)
                let c = Wrapper {
                    inputs: inputs.clone(),
                    params: inner_params.clone(),
                    proof: inner_proof.clone(),
                };
                // Create a groth16 proof with our parameters.
                create_random_proof(c, &params, rng).unwrap()
            };

            let cs = ConstraintSystem::<MNT4Fq>::new_ref();

            let inputs: Vec<_> = inputs.into_iter().map(|input| input.unwrap()).collect();
            let mut input_gadgets = Vec::new();

            {
                let bigint_size = <MNT4FqParameters as FftParameters>::BigInt::NUM_LIMBS * 64;
                let mut input_bits = Vec::new();
                for (i, input) in inputs.into_iter().enumerate() {
                    let input_gadget =
                        FpVar::new_input(cs.ns(format!("Input {}", i)), || Ok(input)).unwrap();
                    let mut fp_bits = input_gadget.to_bits().unwrap();

                    // FpVar::to_bits outputs a big-endian binary representation of
                    // fe_gadget's value, so we have to reverse it to get the little-endian
                    // form.
                    fp_bits.reverse();

                    // Use 320 bits per element.
                    for _ in fp_bits.len()..bigint_size {
                        fp_bits.push(Boolean::constant(false));
                    }
                    input_bits.extend_from_slice(&fp_bits);
                }

                // Pack input bits into field elements of the underlying circuit.
                let max_size = 8 * (<MNT6FqParameters as FpParameters>::CAPACITY / 8) as usize;
                let max_size = max_size as usize;
                let bigint_size = <MNT6FqParameters as FftParameters>::BigInt::NUM_LIMBS * 64;
                for chunk in input_bits.chunks(max_size) {
                    let mut chunk = chunk.to_vec();
                    let len = chunk.len();
                    for _ in len..bigint_size {
                        chunk.push(Boolean::constant(false));
                    }
                    input_gadgets.push(chunk);
                }
                // assert!(!verify_proof(&pvk, &proof, &[a]).unwrap());
            }

            let vk_gadget = TestVkVar2::new_input(cs.ns("Vk"), || Ok(&params.vk)).unwrap();
            let proof_gadget =
                TestProofVar2::new_witness(cs.ns("Proof"), || Ok(proof.clone())).unwrap();
            println!("Time to verify!\n\n\n\n");
            <TestVerifierGadget2 as NIZKVerifierGadget<TestProofSystem2, MNT4Fq>>::verify(
                &vk_gadget,
                input_gadgets.iter(),
                &proof_gadget,
            )
            .unwrap();
            if !cs.is_satisfied().unwrap() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{:?}", cs.which_is_unsatisfied().unwrap());
                println!("=========================================================");
            }

            // cs.print_named_objects();
            assert!(cs.is_satisfied().unwrap());
        }
    }
}
