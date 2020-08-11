use algebra::bls12_377::{Fq, Fq12Parameters, Fq2Parameters, Fq6Parameters};

use crate::fields::{fp::FpVar, fp12::Fp12Var, fp2::Fp2Var, fp6_3over2::Fp6Var};

pub type FqVar = FpVar<Fq>;
pub type Fq2Var = Fp2Var<Fq2Parameters>;
pub type Fq6Var = Fp6Var<Fq6Parameters>;
pub type Fq12Var = Fp12Var<Fq12Parameters>;

#[test]
fn bls12_377_field_test() {
    use super::*;
    use crate::fields::tests::*;
    use algebra::bls12_377::{Fq, Fq12, Fq2, Fq6};

    field_test::<_, FqVar>().unwrap();
    frobenius_tests::<Fq, FqVar>(13).unwrap();

    field_test::<_, Fq2Var>().unwrap();
    frobenius_tests::<Fq2, Fq2Var>(13).unwrap();

    field_test::<_, Fq6Var>().unwrap();
    frobenius_tests::<Fq6, Fq6Var>(13).unwrap();

    field_test::<_, Fq12Var>().unwrap();
    frobenius_tests::<Fq12, Fq12Var>(13).unwrap();
}
