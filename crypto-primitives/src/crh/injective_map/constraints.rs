use core::{fmt::Debug, marker::PhantomData};

use crate::crh::{
    injective_map::{InjectiveMap, PedersenCRHCompressor, TECompressor},
    pedersen::{constraints as ped_constraints, Window},
    FixedLengthCRHGadget,
};

use algebra_core::{
    curves::{
        models::{ModelParameters, TEModelParameters},
        twisted_edwards_extended::GroupProjective as TEProjective,
    },
    fields::{PrimeField, SquareRootField},
    ProjectiveCurve,
};
use r1cs_core::SynthesisError;
use r1cs_std::{
    fields::fp::FpVar,
    groups::{curves::twisted_edwards::AffineVar as TEVar, CurveVar},
    prelude::*,
};

pub trait InjectiveMapGadget<C: ProjectiveCurve, I: InjectiveMap<C>, GG: CurveVar<C>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type OutputVar: EqGadget<GG::ConstraintF>
        + ToBytesGadget<GG::ConstraintF>
        + CondSelectGadget<GG::ConstraintF>
        + AllocVar<I::Output, GG::ConstraintF>
        + R1CSVar<GG::ConstraintF, Value = I::Output>
        + Debug
        + Clone
        + Sized;

    fn evaluate(ge: &GG) -> Result<Self::OutputVar, SynthesisError>;
}

pub struct TECompressorGadget;

impl<F, P> InjectiveMapGadget<TEProjective<P>, TECompressor, TEVar<P, FpVar<F>>>
    for TECompressorGadget
where
    F: PrimeField + SquareRootField,
    P: TEModelParameters + ModelParameters<BaseField = F>,
{
    type OutputVar = FpVar<F>;

    fn evaluate(ge: &TEVar<P, FpVar<F>>) -> Result<Self::OutputVar, SynthesisError> {
        Ok(ge.x.clone())
    }
}

pub struct PedersenCRHCompressorGadget<C, I, W, GG, IG>
where
    C: ProjectiveCurve,
    I: InjectiveMap<C>,
    W: Window,
    GG: CurveVar<C>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    IG: InjectiveMapGadget<C, I, GG>,
{
    #[doc(hidden)]
    _compressor: PhantomData<I>,
    #[doc(hidden)]
    _compressor_gadget: PhantomData<IG>,
    #[doc(hidden)]
    _crh: ped_constraints::CRHGadget<C, GG, W>,
}

impl<C, I, GG, IG, W> FixedLengthCRHGadget<PedersenCRHCompressor<C, I, W>, GG::ConstraintF>
    for PedersenCRHCompressorGadget<C, I, W, GG, IG>
where
    C: ProjectiveCurve,
    I: InjectiveMap<C>,
    GG: CurveVar<C>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    IG: InjectiveMapGadget<C, I, GG>,
    W: Window,
{
    type OutputVar = IG::OutputVar;
    type ParametersVar = ped_constraints::CRHParametersVar<C, GG>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[UInt8<GG::ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let result = ped_constraints::CRHGadget::<C, GG, W>::evaluate(parameters, input)?;
        IG::evaluate(&result)
    }
}
