use advanced_circuit_component::{
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::allocated_num::Num,
    },
    rescue_poseidon::{CircuitGenericSponge, GenericSponge, PoseidonParams},
};
use pairing::Engine;
const WIDTH: usize = 3;
const RATE: usize = 2;

pub fn circuit_poseidon_hash<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    input: &[Num<E>],
) -> Result<Num<E>, SynthesisError> {
    let params = PoseidonParams::<E, RATE, WIDTH>::default();
    Ok(CircuitGenericSponge::hash_num(cs, input, &params, None)?[0])
}

pub fn poseidon_hash<E: Engine>(input: &[E::Fr]) -> E::Fr {
    let params = PoseidonParams::<E, RATE, WIDTH>::default();
    GenericSponge::hash(input, &params, None)[0]
}
