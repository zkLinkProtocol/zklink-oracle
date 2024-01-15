use crate::franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use crate::franklin_crypto::bellman::SynthesisError;
use crate::franklin_crypto::plonk::circuit::allocated_num::Num;
use pairing::Engine;
use sync_vm::rescue_poseidon::{CircuitGenericSponge, CustomGate, HashParams, RescueParams};

pub fn circuit_rescue_hash<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    input: &[Num<E>],
) -> Result<Num<E>, SynthesisError> {
    let mut params = RescueParams::specialized_for_num_rounds(5, 100); // Alignment with bn254_rescue_params function
    params.use_custom_gate(CustomGate::QuinticWidth4); // Above
    Ok(CircuitGenericSponge::<E, 2, 3>::hash_num(cs, input, &params, None)?[0])
}
