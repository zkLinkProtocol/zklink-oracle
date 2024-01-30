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
    pub prices_commitment: PricesSummarize<E>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PricesSummarize<E: Engine> {
    pub commitment: E::Fr,
    pub num: E::Fr,
    pub base_sum: E::Fr,
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
    pub price_summarize: OraclePriceSummarize<E>,
}

impl<E: Engine> CircuitEmpty<E> for OracleOutputData<E> {
    fn empty() -> Self {
        Self {
            guardian_set_hash: Num::zero(),
            earliest_publish_time: Num::zero(),
            price_summarize: CircuitEmpty::empty(),
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
pub struct OraclePriceSummarize<E: Engine> {
    pub commitment: Num<E>,
    pub num: Num<E>,
    pub commitment_base_sum: Num<E>, // public input
}

impl<E: Engine> CircuitEmpty<E> for OraclePriceSummarize<E> {
    fn empty() -> Self {
        Self {
            commitment: Num::zero(),
            num: Num::zero(),
            commitment_base_sum: Num::zero(),
        }
    }
}
