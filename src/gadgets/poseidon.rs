use pairing::Engine;
use sync_vm::{
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::allocated_num::Num,
    },
    rescue_poseidon::{CircuitGenericSponge, DomainStrategy, HashParams, PoseidonParams},
};

pub fn circuit_poseidon_hash<E: Engine, CS: ConstraintSystem<E>, const L: usize>(
    cs: &mut CS,
    input: &[Num<E>; L],
) -> Result<[Num<E>; 2], SynthesisError> {
    const WIDTH: usize = 3;
    const RATE: usize = 2;
    let params = PoseidonParams::<E, RATE, WIDTH>::default();
    circuit_generic_hash_num(cs, input, &params, None)
}

pub fn circuit_generic_hash_num<
    E: Engine,
    CS: ConstraintSystem<E>,
    P: HashParams<E, RATE, WIDTH>,
    const RATE: usize,
    const WIDTH: usize,
    const LENGTH: usize,
>(
    cs: &mut CS,
    input: &[Num<E>; LENGTH],
    params: &P,
    domain_strategy: Option<DomainStrategy>,
) -> Result<[Num<E>; RATE], SynthesisError> {
    CircuitGenericSponge::hash_num(cs, input, params, domain_strategy)
}
