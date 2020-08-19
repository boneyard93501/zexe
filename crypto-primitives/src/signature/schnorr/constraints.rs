use crate::Vec;
use algebra_core::ProjectiveCurve;
use r1cs_core::{Namespace, SynthesisError};
use r1cs_std::prelude::*;

use crate::signature::SigRandomizePkGadget;

use core::{borrow::Borrow, marker::PhantomData};

use crate::signature::schnorr::{Parameters, PublicKey, Schnorr};
use digest::Digest;

#[derive(Clone)]
pub struct ParametersVar<C: ProjectiveCurve, GC: CurveVar<C>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    generator: GC,
    _curve: PhantomData<C>,
}

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: ProjectiveCurve, GC: CurveVar<C>"),
    Clone(bound = "C: ProjectiveCurve, GC: CurveVar<C>")
)]
pub struct PublicKeyVar<C: ProjectiveCurve, GC: CurveVar<C>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    pub_key: GC,
    #[doc(hidden)]
    _group: PhantomData<*const C>,
}

pub struct SchnorrRandomizePkGadget<C: ProjectiveCurve, GC: CurveVar<C>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

impl<C, GC, D> SigRandomizePkGadget<Schnorr<C, D>, GC::ConstraintF>
    for SchnorrRandomizePkGadget<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C>,
    D: Digest + Send + Sync,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;

    fn randomize(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        randomness: &[UInt8<GC::ConstraintF>],
    ) -> Result<Self::PublicKeyVar, SynthesisError> {
        let base = parameters.generator.clone();
        let randomness = randomness
            .iter()
            .flat_map(|b| b.into_bits_le())
            .collect::<Vec<_>>();
        let rand_pk = &public_key.pub_key + &base.mul_bits(randomness.iter())?;
        Ok(PublicKeyVar {
            pub_key: rand_pk,
            _group: PhantomData,
        })
    }
}

impl<C, GC, D> AllocVar<Parameters<C, D>, GC::ConstraintF> for ParametersVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C>,
    D: Digest,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<Parameters<C, D>>>(
        cs: impl Into<Namespace<GC::ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = GC::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        Ok(Self {
            generator,
            _curve: PhantomData,
        })
    }
}

impl<C, GC> AllocVar<PublicKey<C>, GC::ConstraintF> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<GC::ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pub_key = GC::new_variable(cs, f, mode)?;
        Ok(Self {
            pub_key,
            _group: PhantomData,
        })
    }
}

impl<C, GC> EqGadget<GC::ConstraintF> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<GC::ConstraintF>, SynthesisError> {
        self.pub_key.is_eq(&other.pub_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<GC::ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_equal(&other.pub_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<GC::ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_not_equal(&other.pub_key, condition)
    }
}

impl<C, GC> ToBytesGadget<GC::ConstraintF> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<GC::ConstraintF>>, SynthesisError> {
        self.pub_key.to_bytes()
    }
}
