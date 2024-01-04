use pairing::Engine;
use sync_vm::{
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::allocated_num::Num,
    },
    rescue_poseidon::{CircuitGenericSponge, GenericSponge, PoseidonParams},
};
const WIDTH: usize = 3;
const RATE: usize = 2;

pub fn circuit_poseidon_hash<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    input: &[Num<E>],
) -> Result<[Num<E>; RATE], SynthesisError> {
    let params = PoseidonParams::<E, RATE, WIDTH>::default();
    CircuitGenericSponge::hash_num(cs, input, &params, None)
}

pub fn poseidon_hash<E: Engine>(input: &[E::Fr]) -> [E::Fr; RATE] {
    let params = PoseidonParams::<E, RATE, WIDTH>::default();
    GenericSponge::hash(input, &params, None)
}
