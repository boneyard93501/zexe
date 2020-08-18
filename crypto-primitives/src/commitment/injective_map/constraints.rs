use crate::commitment::{
    injective_map::{InjectiveMap, PedersenCommCompressor},
    pedersen::{
        constraints::{CommGadget, ParametersVar, RandomnessVar},
        Window,
    },
};

pub use crate::crh::injective_map::constraints::InjectiveMapGadget;
use algebra_core::{PrimeField, ProjectiveCurve};
use r1cs_core::SynthesisError;
use r1cs_std::{
    groups::{CurveVar, GroupOpsBounds},
    uint8::UInt8,
};

use core::marker::PhantomData;

pub struct CommitmentCompressorGadget<C, I, W, GG, IG>
where
    C: ProjectiveCurve,
    I: InjectiveMap<C>,
    W: Window,
    GG: CurveVar<C>,
    IG: InjectiveMapGadget<C, I, GG>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    _compressor: PhantomData<I>,
    _compressor_gadget: PhantomData<IG>,
    _comm: PhantomData<CommGadget<C, GG, W>>,
}

impl<C, I, GG, IG, W>
    crate::commitment::CommitmentGadget<PedersenCommCompressor<C, I, W>, GG::ConstraintF>
    for CommitmentCompressorGadget<C, I, W, GG, IG>
where
    C: ProjectiveCurve,
    I: InjectiveMap<C>,
    GG: CurveVar<C>,
    <GG as CurveVar<C>>::ConstraintF: PrimeField,
    IG: InjectiveMapGadget<C, I, GG>,
    W: Window,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type OutputVar = IG::OutputVar;
    type ParametersVar = ParametersVar<C, GG>;
    type RandomnessVar = RandomnessVar<GG::ConstraintF>;

    fn commit(
        parameters: &Self::ParametersVar,
        input: &[UInt8<GG::ConstraintF>],
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let result = CommGadget::<C, GG, W>::commit(parameters, input, r)?;
        IG::evaluate(&result)
    }
}
