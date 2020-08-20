use algebra::{
    fields::{FftParameters, FpParameters},
    BigInteger, Field, PrimeField,
};
use algebra_core::{PairingEngine, ToConstraintField};
use crypto_primitives::nizk::{
    constraints::NIZKVerifierGadget,
    groth16::{
        constraints::{Groth16VerifierGadget, ProofVar, VerifyingKeyVar},
        Groth16,
    },
};
use groth16::{Parameters, Proof};
use r1cs_core::{lc, ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use r1cs_std::{
    alloc::AllocVar, bits::ToBitsGadget, boolean::Boolean, fields::fp::FpVar,
    pairing::PairingVar as PG, uint8::UInt8,
};
use std::marker::PhantomData;

pub trait CurvePair {
    type TickGroup: PairingEngine<Fq = <Self::TockGroup as PairingEngine>::Fr>;
    type TockGroup: PairingEngine<Fq = <Self::TickGroup as PairingEngine>::Fr>;
    type PairingVarTick: PG<Self::TickGroup>;
    type PairingVarTock: PG<Self::TockGroup>;

    const TICK_CURVE: &'static str;
    const TOCK_CURVE: &'static str;
}

// Verifying InnerCircuit in MiddleCircuit
type InnerProofSystem<C> = Groth16<
    <C as CurvePair>::TickGroup,
    InnerCircuit<<<C as CurvePair>::TickGroup as PairingEngine>::Fr>,
    <<C as CurvePair>::TickGroup as PairingEngine>::Fr,
>;
type InnerVerifierGadget<C> =
    Groth16VerifierGadget<<C as CurvePair>::TickGroup, <C as CurvePair>::PairingVarTick>;
type InnerProofVar<C> = ProofVar<<C as CurvePair>::TickGroup, <C as CurvePair>::PairingVarTick>;
type InnerVkVar<C> = VerifyingKeyVar<<C as CurvePair>::TickGroup, <C as CurvePair>::PairingVarTick>;

// Verifying MiddleCircuit in OuterCircuit
type MiddleProofSystem<C> = Groth16<
    <C as CurvePair>::TockGroup,
    MiddleCircuit<C>,
    <<C as CurvePair>::TockGroup as PairingEngine>::Fr,
>;
type MiddleVerifierGadget<C> =
    Groth16VerifierGadget<<C as CurvePair>::TockGroup, <C as CurvePair>::PairingVarTock>;
type MiddleProofVar<C> = ProofVar<<C as CurvePair>::TockGroup, <C as CurvePair>::PairingVarTock>;
type MiddleVkVar<C> =
    VerifyingKeyVar<<C as CurvePair>::TockGroup, <C as CurvePair>::PairingVarTock>;

pub struct InnerCircuit<F: Field> {
    num_constraints: usize,
    inputs: Vec<F>,
}

impl<F: Field> InnerCircuit<F> {
    pub fn new(num_constraints: usize, inputs: Vec<F>) -> Self {
        Self {
            num_constraints,
            inputs,
        }
    }
}

impl<F: Field> ConstraintSynthesizer<F> for InnerCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        assert!(self.inputs.len() >= 2);
        assert!(self.num_constraints >= self.inputs.len());

        let mut variables: Vec<_> = Vec::with_capacity(self.inputs.len());
        for (i, input) in self.inputs.into_iter().enumerate() {
            let input_var = cs.new_input_variable(|| Ok(input))?;
            variables.push((input, input_var));
        }

        for i in 0..self.num_constraints {
            let new_entry = {
                let (input_1_val, input_1_var) = variables[i];
                let (input_2_val, input_2_var) = variables[i + 1];
                let result_val = input_1_val * input_2_val;
                let result_var = cs.new_witness_variable(|| Ok(result_val))?;
                cs.enforce_named_constraint(
                    format!("Enforce constraint {}", i),
                    lc!() + input_1_var,
                    lc!() + input_2_var,
                    lc!() + result_var,
                );
                (result_val, result_var)
            };
            variables.push(new_entry);
        }
        Ok(())
    }
}

pub struct MiddleCircuit<C: CurvePair> {
    inputs: Vec<<C::TickGroup as PairingEngine>::Fr>,
    params: Parameters<C::TickGroup>,
    proof: Proof<C::TickGroup>,
    _curve_pair: PhantomData<C>,
}

impl<C: CurvePair> MiddleCircuit<C> {
    pub fn new(
        inputs: Vec<<C::TickGroup as PairingEngine>::Fr>,
        params: Parameters<C::TickGroup>,
        proof: Proof<C::TickGroup>,
    ) -> Self {
        Self {
            inputs,
            params,
            proof,
            _curve_pair: PhantomData,
        }
    }

    pub fn inputs(
        inputs: &[<C::TickGroup as PairingEngine>::Fr],
    ) -> Vec<<C::TockGroup as PairingEngine>::Fr> {
        let input_bytes = inputs
            .iter()
            .flat_map(|input| {
                input
                    .into_repr()
                    .as_ref()
                    .iter()
                    .flat_map(|l| l.to_le_bytes().to_vec())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        input_bytes[..].to_field_elements().unwrap()
    }
}

impl<C: CurvePair> ConstraintSynthesizer<<C::TockGroup as PairingEngine>::Fr> for MiddleCircuit<C> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<<C::TockGroup as PairingEngine>::Fr>,
    ) -> Result<(), SynthesisError> {
        let params = self.params;
        let proof = self.proof;
        let inputs = self.inputs;
        let input_gadgets;

        {
            let ns = cs.ns("Allocate Input");
            let cs = ns.cs();
            // Chain all input values in one large byte array.
            let input_bytes = inputs
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
            let element_size =
                <<<C::TickGroup as PairingEngine>::Fr as PrimeField>::Params as FftParameters>::BigInt::NUM_LIMBS * 8;
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
        println!("|---- Num inputs for sub-SNARK: {}", input_gadgets.len());
        let num_constraints = cs.num_constraints();
        println!(
            "|---- Num constraints to prepare inputs: {}",
            num_constraints
        );

        let vk_gadget = InnerVkVar::<C>::new_witness(cs.ns("Vk"), || Ok(&params.vk))?;
        let proof_gadget = InnerProofVar::<C>::new_witness(cs.ns("Proof"), || Ok(proof.clone()))?;
        <InnerVerifierGadget<C> as NIZKVerifierGadget<
            InnerProofSystem<C>,
            <C::TockGroup as PairingEngine>::Fr,
        >>::verify(&vk_gadget, input_gadgets.iter(), &proof_gadget)?;
        println!(
            "|---- Num constraints for sub-SNARK verification: {}",
            cs.num_constraints() - num_constraints
        );
        Ok(())
    }
}

pub struct OuterCircuit<C: CurvePair> {
    inputs: Vec<<C::TickGroup as PairingEngine>::Fr>,
    params: Parameters<C::TockGroup>,
    proof: Proof<C::TockGroup>,
    _curve_pair: PhantomData<C>,
}

impl<C: CurvePair> OuterCircuit<C> {
    pub fn new(
        inputs: Vec<<C::TickGroup as PairingEngine>::Fr>,
        params: Parameters<C::TockGroup>,
        proof: Proof<C::TockGroup>,
    ) -> Self {
        Self {
            inputs,
            params,
            proof,
            _curve_pair: PhantomData,
        }
    }
}

impl<C: CurvePair> ConstraintSynthesizer<<C::TickGroup as PairingEngine>::Fr> for OuterCircuit<C> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<<C::TickGroup as PairingEngine>::Fr>,
    ) -> Result<(), SynthesisError> {
        let params = self.params;
        let proof = self.proof;
        let inputs = self.inputs;
        let mut input_gadgets = Vec::new();

        {
            let bigint_size =
                <<<C::TickGroup as PairingEngine>::Fr as PrimeField>::Params as FftParameters>::BigInt::NUM_LIMBS * 64;
            let mut input_bits = Vec::new();
            let mut cs = cs.ns("Allocate Input");
            for (i, input) in inputs.into_iter().enumerate() {
                let input_gadget = FpVar::new_input(cs.ns(format!("Input {}", i)), || Ok(input))?;
                let mut fp_bits = input_gadget.to_bits(cs.ns(format!("To bits {}", i)))?;

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
            let max_size = 8
                * (<<<C::TockGroup as PairingEngine>::Fr as PrimeField>::Params as FpParameters>::CAPACITY / 8)
                    as usize;
            let bigint_size =
                <<<C::TockGroup as PairingEngine>::Fr as PrimeField>::Params as FftParameters>::BigInt::NUM_LIMBS * 64;
            for chunk in input_bits.chunks(max_size) {
                let mut chunk = chunk.to_vec();
                let len = chunk.len();
                for _ in len..bigint_size {
                    chunk.push(Boolean::constant(false));
                }
                input_gadgets.push(chunk);
            }
        }
        println!("|---- Num inputs for sub-SNARK: {}", input_gadgets.len());
        let num_constraints = cs.num_constraints();
        println!(
            "|---- Num constraints to prepare inputs: {}",
            num_constraints
        );

        let vk_gadget = MiddleVkVar::<C>::new_witness(cs.ns("Vk"), || Ok(&params.vk))?;
        let proof_gadget = MiddleProofVar::<C>::new_witness(cs.ns("Proof"), || Ok(proof.clone()))?;
        <MiddleVerifierGadget<C> as NIZKVerifierGadget<
            MiddleProofSystem<C>,
            <C::TickGroup as PairingEngine>::Fr,
        >>::verify(&vk_gadget, input_gadgets.iter(), &proof_gadget)?;
        println!(
            "|---- Num constraints for sub-SNARK verification: {}",
            cs.num_constraints() - num_constraints
        );
        Ok(())
    }
}
