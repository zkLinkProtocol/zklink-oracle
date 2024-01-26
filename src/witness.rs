use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use advanced_circuit_component::franklin_crypto::bellman::Engine;
use advanced_circuit_component::franklin_crypto::bellman::SynthesisError;
use advanced_circuit_component::franklin_crypto::plonk::circuit::allocated_num::Num;
use advanced_circuit_component::franklin_crypto::plonk::circuit::boolean::Boolean;
use advanced_circuit_component::traits::*;
use advanced_circuit_component::vm::structural_eq::*;
use cs_derive::*;
use derivative::Derivative;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PublicInputData<E: Engine> {
    pub guardian_set_hash: E::Fr,
    pub earliest_publish_time: E::Fr,
    pub prices_commitment: PricesCommitment<E>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PricesCommitment<E: Engine> {
    pub prices_commitment: E::Fr,
    pub prices_num: E::Fr,
    pub prices_commitment_base_sum: E::Fr,
}

#[derive(
    Derivative,
    CSAllocatable,
    CSWitnessable,
    CSPackable,
    CSSelectable,
    CSEqual,
    CSEncodable,
    CSDecodable,
    CSVariableLengthEncodable,
)]
#[derivative(Clone, Debug)]
pub struct OracleOutputData<E: Engine> {
    pub guardian_set_hash: Num<E>,
    pub earliest_publish_time: Num<E>,
    pub prices_commitment: OraclePricesCommitment<E>,
}

impl<E: Engine> CircuitEmpty<E> for OracleOutputData<E> {
    fn empty() -> Self {
        Self {
            guardian_set_hash: Num::zero(),
            earliest_publish_time: Num::zero(),
            prices_commitment: CircuitEmpty::empty(),
        }
    }
}

#[derive(
    Derivative,
    CSAllocatable,
    CSWitnessable,
    CSPackable,
    CSSelectable,
    CSEqual,
    CSEncodable,
    CSDecodable,
    CSVariableLengthEncodable,
)]
#[derivative(Clone, Debug)]
pub struct OraclePricesCommitment<E: Engine> {
    pub prices_commitment: Num<E>,
    pub prices_num: Num<E>,
    pub prices_commitment_base_sum: Num<E>, // public input
}

impl<E: Engine> CircuitEmpty<E> for OraclePricesCommitment<E> {
    fn empty() -> Self {
        Self {
            prices_commitment: Num::zero(),
            prices_num: Num::zero(),
            prices_commitment_base_sum: Num::zero(),
        }
    }
}
