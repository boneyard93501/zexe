use crate::prelude::*;
use algebra::{Field, PairingEngine};
use core::fmt::Debug;
use r1cs_core::SynthesisError;

pub mod bls12;
pub mod mnt4;
pub mod mnt6;

pub trait PairingVar<E: PairingEngine>
where
    for<'a> &'a Self::G1Var: GroupOpsBounds<'a, E::G1Projective, Self::G1Var>,
    for<'a> &'a Self::G2Var: GroupOpsBounds<'a, E::G2Projective, Self::G2Var>,
    for<'a> &'a Self::GTVar: FieldOpsBounds<'a, E::Fqk, Self::GTVar>,
{
    type ConstraintF: Field;
    // TODO: there are some ugly hacks here where we have to reproduce the bounds
    // unnecessarily. Maybe there's an issue tracking this?

    type G1Var: CurveVar<E::G1Projective, ConstraintF = Self::ConstraintF>
        + R1CSVar<Self::ConstraintF, Value = E::G1Projective>
        + EqGadget<Self::ConstraintF>
        + ToBitsGadget<Self::ConstraintF>
        + AllocVar<E::G1Projective, Self::ConstraintF>
        + AllocVar<E::G1Affine, Self::ConstraintF>
        + ToBytesGadget<Self::ConstraintF>
        + CondSelectGadget<Self::ConstraintF>;

    type G2Var: CurveVar<E::G2Projective, ConstraintF = Self::ConstraintF>
        + R1CSVar<Self::ConstraintF, Value = E::G2Projective>
        + EqGadget<Self::ConstraintF>
        + ToBitsGadget<Self::ConstraintF>
        + AllocVar<E::G2Projective, Self::ConstraintF>
        + AllocVar<E::G2Affine, Self::ConstraintF>
        + ToBytesGadget<Self::ConstraintF>
        + CondSelectGadget<Self::ConstraintF>;

    type G1PreparedVar: ToBytesGadget<Self::ConstraintF>
        + AllocVar<E::G1Prepared, Self::ConstraintF>
        + Clone
        + Debug;
    type G2PreparedVar: ToBytesGadget<Self::ConstraintF>
        + AllocVar<E::G2Prepared, Self::ConstraintF>
        + Clone
        + Debug;
    type GTVar: FieldVar<E::Fqk, ConstraintF = Self::ConstraintF>
        + From<Boolean<Self::ConstraintF>>
        + R1CSVar<Self::ConstraintF, Value = E::Fqk>
        + EqGadget<Self::ConstraintF>
        + ToBitsGadget<Self::ConstraintF>
        + AllocVar<E::Fqk, Self::ConstraintF>
        + ToBytesGadget<Self::ConstraintF>
        + CondSelectGadget<Self::ConstraintF>;

    fn miller_loop(
        p: &[Self::G1PreparedVar],
        q: &[Self::G2PreparedVar],
    ) -> Result<Self::GTVar, SynthesisError>;

    fn final_exponentiation(p: &Self::GTVar) -> Result<Self::GTVar, SynthesisError>;

    fn pairing(
        p: Self::G1PreparedVar,
        q: Self::G2PreparedVar,
    ) -> Result<Self::GTVar, SynthesisError> {
        let tmp = Self::miller_loop(&[p], &[q])?;
        Self::final_exponentiation(&tmp)
    }

    /// Computes a product of pairings.
    #[must_use]
    fn product_of_pairings(
        p: &[Self::G1PreparedVar],
        q: &[Self::G2PreparedVar],
    ) -> Result<Self::GTVar, SynthesisError> {
        let miller_result = Self::miller_loop(p, q)?;
        Self::final_exponentiation(&miller_result)
    }

    fn prepare_g1(q: &Self::G1Var) -> Result<Self::G1PreparedVar, SynthesisError>;

    fn prepare_g2(q: &Self::G2Var) -> Result<Self::G2PreparedVar, SynthesisError>;
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{prelude::*, Vec};
    use algebra::{test_rng, BitIterator, Field, PairingEngine, PrimeField, UniformRand};
    use r1cs_core::{ConstraintSystem, SynthesisError};

    #[allow(dead_code)]
    pub(crate) fn bilinearity_test<E: PairingEngine, P: PairingVar<E>>(
    ) -> Result<(), SynthesisError>
    where
        for<'a> &'a P::G1Var: GroupOpsBounds<'a, E::G1Projective, P::G1Var>,
        for<'a> &'a P::G2Var: GroupOpsBounds<'a, E::G2Projective, P::G2Var>,
        for<'a> &'a P::GTVar: FieldOpsBounds<'a, E::Fqk, P::GTVar>,
    {
        let cs = ConstraintSystem::<P::ConstraintF>::new_ref();

        let mut rng = test_rng();
        let a = E::G1Projective::rand(&mut rng);
        let b = E::G2Projective::rand(&mut rng);
        let s = E::Fr::rand(&mut rng);

        let mut sa = a;
        sa *= s;
        let mut sb = b;
        sb *= s;

        let a_g = P::G1Var::new_witness(cs.ns("a"), || Ok(a))?;
        let b_g = P::G2Var::new_witness(cs.ns("b"), || Ok(b))?;
        let sa_g = P::G1Var::new_witness(cs.ns("sa"), || Ok(sa))?;
        let sb_g = P::G2Var::new_witness(cs.ns("sb"), || Ok(sb))?;

        let a_prep_g = P::prepare_g1(&a_g)?;
        let b_prep_g = P::prepare_g2(&b_g)?;

        let sa_prep_g = P::prepare_g1(&sa_g)?;
        let sb_prep_g = P::prepare_g2(&sb_g)?;

        let (ans1_g, ans1_n) = {
            let ans_g = P::pairing(sa_prep_g, b_prep_g.clone())?;
            let ans_n = E::pairing(sa, b);
            (ans_g, ans_n)
        };

        let (ans2_g, ans2_n) = {
            let ans_g = P::pairing(a_prep_g.clone(), sb_prep_g)?;
            let ans_n = E::pairing(a, sb);
            (ans_g, ans_n)
        };

        let (ans3_g, ans3_n) = {
            let s_iter = BitIterator::new(s.into_repr())
                .map(Boolean::constant)
                .collect::<Vec<_>>();

            let mut ans_g = P::pairing(a_prep_g, b_prep_g)?;
            let mut ans_n = E::pairing(a, b);
            ans_n = ans_n.pow(s.into_repr());
            ans_g = ans_g.pow(&s_iter)?;

            (ans_g, ans_n)
        };

        ans1_g.enforce_equal(&ans2_g)?;
        ans2_g.enforce_equal(&ans3_g)?;

        assert_eq!(ans1_g.value()?, ans1_n, "Failed native test 1");
        assert_eq!(ans2_g.value()?, ans2_n, "Failed native test 2");
        assert_eq!(ans3_g.value()?, ans3_n, "Failed native test 3");

        assert_eq!(ans1_n, ans2_n, "Failed ans1_native == ans2_native");
        assert_eq!(ans2_n, ans3_n, "Failed ans2_native == ans3_native");
        assert_eq!(ans1_g.value()?, ans3_g.value()?, "Failed ans1 == ans3");
        assert_eq!(ans1_g.value()?, ans2_g.value()?, "Failed ans1 == ans2");
        assert_eq!(ans2_g.value()?, ans3_g.value()?, "Failed ans2 == ans3");

        if !cs.is_satisfied().unwrap() {
            println!("Unsatisfied: {:?}", cs.which_is_unsatisfied());
        }

        assert!(cs.is_satisfied().unwrap(), "cs is not satisfied");
        Ok(())
    }
}
