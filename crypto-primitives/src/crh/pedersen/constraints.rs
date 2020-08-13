use crate::{
    crh::{
        pedersen::{Parameters, Window, CRH},
        FixedLengthCRHGadget,
    },
    Vec,
};
use algebra_core::ProjectiveCurve;
use r1cs_core::{Namespace, SynthesisError};
use r1cs_std::prelude::*;

use core::{borrow::Borrow, marker::PhantomData};

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve, GG: GroupVar<C>"))]
pub struct CRHParametersVar<C: ProjectiveCurve, GG: GroupVar<C>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    params: Parameters<C>,
    #[doc(hidden)]
    _group_g: PhantomData<GG>,
}

pub struct CRHGadget<C: ProjectiveCurve, GG: GroupVar<C>, W: Window>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_var: PhantomData<*const GG>,
    #[doc(hidden)]
    _window: PhantomData<*const W>,
}

impl<C, GG, W> FixedLengthCRHGadget<CRH<C, W>, GG::ConstraintF> for CRHGadget<C, GG, W>
where
    C: ProjectiveCurve,
    GG: GroupVar<C>,
    W: Window,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type OutputVar = GG;
    type ParametersVar = CRHParametersVar<C, GG>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[UInt8<GG::ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let mut padded_input = input.to_vec();
        // Pad the input if it is not the current length.
        if input.len() * 8 < W::WINDOW_SIZE * W::NUM_WINDOWS {
            let current_length = input.len();
            for _ in current_length..(W::WINDOW_SIZE * W::NUM_WINDOWS / 8) {
                padded_input.push(UInt8::constant(0u8));
            }
        }
        assert_eq!(padded_input.len() * 8, W::WINDOW_SIZE * W::NUM_WINDOWS);
        assert_eq!(parameters.params.generators.len(), W::NUM_WINDOWS);

        // Allocate new variable for the result.
        let input_in_bits: Vec<_> = padded_input.iter().flat_map(|b| b.into_bits_le()).collect();
        let input_in_bits = input_in_bits.chunks(W::WINDOW_SIZE);
        let result =
            GG::precomputed_base_multiscalar_mul(&parameters.params.generators, input_in_bits)?;

        Ok(result)
    }
}

impl<C, GG> AllocVar<Parameters<C>, GG::ConstraintF> for CRHParametersVar<C, GG>
where
    C: ProjectiveCurve,
    GG: GroupVar<C>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        _cs: impl Into<Namespace<GG::ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();
        Ok(CRHParametersVar {
            params,
            _group_g: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::crh::{pedersen, pedersen::constraints::*, FixedLengthCRH, FixedLengthCRHGadget};
    use algebra::{
        ed_on_bls12_381::{EdwardsProjective as JubJub, Fq as Fr},
        test_rng, ProjectiveCurve,
    };
    use r1cs_core::{ConstraintSystem, ConstraintSystemRef};
    use r1cs_std::ed_on_bls12_381::EdwardsVar;
    use rand::Rng;

    type TestCRH = pedersen::CRH<JubJub, Window>;
    type TestCRHGadget = CRHGadget<JubJub, EdwardsVar, Window>;

    #[derive(Clone, PartialEq, Eq, Hash)]
    pub(super) struct Window;

    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 128;
        const NUM_WINDOWS: usize = 8;
    }

    fn generate_input<R: Rng>(
        cs: ConstraintSystemRef<Fr>,
        rng: &mut R,
    ) -> ([u8; 128], Vec<UInt8<Fr>>) {
        let mut input = [1u8; 128];
        rng.fill_bytes(&mut input);

        let mut input_bytes = vec![];
        for byte in input.iter() {
            input_bytes.push(UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap());
        }
        (input, input_bytes)
    }

    #[test]
    fn test_native_equality() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let (input, input_var) = generate_input(cs.clone(), rng);

        let parameters = TestCRH::setup(rng).unwrap();
        let primitive_result = TestCRH::evaluate(&parameters, &input).unwrap();

        let parameters_var =
            CRHParametersVar::new_constant(cs.ns("CRH Parameters"), &parameters).unwrap();

        let gadget_result = TestCRHGadget::evaluate(&parameters_var, &input_var).unwrap();

        let primitive_result = primitive_result.into_affine();
        assert_eq!(
            primitive_result,
            gadget_result.value().unwrap().into_affine()
        );
        assert!(cs.is_satisfied().unwrap());
    }
}
