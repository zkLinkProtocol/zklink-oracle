use std::ops::Mul as _;

use advanced_circuit_component::franklin_crypto::bellman::pairing::{
    ff::{Field, PrimeField},
    Engine,
};
use advanced_circuit_component::{
    circuit_structures::byte::Byte,
    franklin_crypto::{
        bellman::{
            plonk::better_better_cs::{
                cs::{Circuit, ConstraintSystem, Gate, GateInternal},
                gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext,
            },
            SynthesisError,
        },
        plonk::circuit::{
            allocated_num::{AllocatedNum, Num},
            boolean::Boolean,
            custom_rescue_gate::Rescue5CustomGate,
        },
    },
    glue::prepacked_long_comparison,
    vm::primitives::{uint256::UInt256, UInt128, UInt64},
};
use bigdecimal::num_traits::FromBytes;
use num_bigint::BigUint;

use crate::{
    gadgets::{
        ethereum::Address,
        poseidon::{circuit_poseidon_hash, poseidon_hash},
        rescue::circuit_rescue_hash,
    },
    utils::{self, fr_from_biguint},
    witness::{PricesSummarize, PublicInputData},
};

use self::{circuit::AllocatedSignedPrice, witness::DataPackage};

pub mod circuit;
pub mod witness;

// Number of bytes reserved to store timestamp
pub const TIMESTAMP_BS: usize = 6;
// Number of bytes reserved to store the number of data points
pub const DATA_POINTS_COUNT_BS: usize = 3;
// Number of bytes reserved to store datapoints byte size
pub const DATA_POINT_VALUE_BYTE_SIZE_BS: usize = 4;
// Default value byte size for numeric values
pub const DEFAULT_NUM_VALUE_BS: usize = 32;
// Default precision for numeric values
pub const DEFAULT_NUM_VALUE_DECIMALS: usize = 8;

pub struct PriceOracle<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICE: usize> {
    pub signed_prices_batch: Vec<[[(DataPackage, [u8; 65]); NUM_SIGNATURES_TO_VERIFY]; NUM_PRICE]>,
    pub guardians: [[u8; 20]; NUM_SIGNATURES_TO_VERIFY],
    pub public_input_data: PublicInputData<E>,
    pub commitment: E::Fr,
}

impl<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICES: usize>
    PriceOracle<E, NUM_SIGNATURES_TO_VERIFY, NUM_PRICES>
{
    pub fn new(
        signed_prices_batch: Vec<[[(DataPackage, [u8; 65]); NUM_SIGNATURES_TO_VERIFY]; NUM_PRICES]>,
        guardian_set: [[u8; 20]; NUM_SIGNATURES_TO_VERIFY],
    ) -> Result<Self, anyhow::Error> {
        let mut last_publish_time = 0;
        let mut earliest_publish_time = 0;
        let mut prices_commitments = vec![];
        for signed_prices in signed_prices_batch.iter() {
            // Check publish time is increasing
            let signed_price = signed_prices[0].clone();
            {
                let current_publish_time = signed_price[0].0.timestamp;
                if current_publish_time < last_publish_time {
                    anyhow::bail!(
                        "publish time is not increasing: {} <= {}",
                        current_publish_time,
                        last_publish_time
                    )
                };
                last_publish_time = current_publish_time;
                if earliest_publish_time == 0 {
                    earliest_publish_time = last_publish_time;
                }
            }

            // Compute price root
            {
                let mut prices_commitment_members = vec![];
                for price_feed in signed_prices.iter() {
                    let (price, _) = price_feed[0].clone();
                    let feed_id = {
                        // Due the limitation of zklink state tree, we can only store first 15 bytes of feed_id
                        let feed_id = price.data_points[0].serialize_feed_id();
                        let mut bytes = [0u8; 16];
                        bytes[1..].copy_from_slice(&feed_id[0..15]);
                        BigUint::from_bytes_be(&bytes)
                    };

                    // normalized_price = 10^18 * real_price
                    let price = {
                        // The fetched price has been multiplied by 10^8
                        let price = {
                            // 32-bytes
                            let bytes = price.data_points[0].serialize_value();
                            BigUint::from_be_bytes(&bytes)
                        };
                        let exponent = (18 - 8) as u32;
                        let coefficient = BigUint::from(10u32).pow(exponent);
                        coefficient.mul(&price)
                    };
                    prices_commitment_members.push(fr_from_biguint::<E>(&feed_id)?);
                    prices_commitment_members.push(fr_from_biguint::<E>(&price)?);
                }
                let prices_commitment = poseidon_hash::<E>(&prices_commitment_members);
                prices_commitments.push(prices_commitment);
            }
        }

        let guardian_set_hash = {
            let input = guardian_set
                .iter()
                .map(|g| {
                    let u = BigUint::from_bytes_be(g);
                    fr_from_biguint::<E>(&u)
                })
                .collect::<Result<Vec<_>, _>>()?;
            poseidon_hash::<E>(&input)
        };

        let earliest_publish_time = fr_from_biguint::<E>(&BigUint::from(earliest_publish_time))?;

        let prices_num = E::Fr::from_str(&prices_commitments.len().to_string()).unwrap();
        let mut prices_commitment_base_sum = E::Fr::zero();
        let mut prices_commitment = E::Fr::zero();
        for (i, mut commitment) in prices_commitments.into_iter().enumerate() {
            Field::add_assign(&mut prices_commitment_base_sum, &commitment);
            let coef = E::Fr::from_str(&format!("{}", i)).unwrap();
            Field::mul_assign(&mut commitment, &coef);
            Field::add_assign(&mut prices_commitment, &commitment);
        }

        let commitment = poseidon_hash::<E>(&[
            guardian_set_hash,
            prices_commitment,
            earliest_publish_time,
            prices_num,
            prices_commitment_base_sum,
        ]);

        Ok(Self {
            commitment,
            public_input_data: PublicInputData {
                guardian_set_hash,
                prices_summarize: PricesSummarize {
                    commitment: prices_commitment,
                    num: prices_num,
                    commitment_base_sum: prices_commitment_base_sum,
                },
                earliest_publish_time,
            },
            signed_prices_batch,
            guardians: guardian_set,
        })
    }
}

impl<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICES: usize> Circuit<E>
    for PriceOracle<E, NUM_SIGNATURES_TO_VERIFY, NUM_PRICES>
{
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        utils::add_bitwise_logic_and_range_table(cs)?;
        let temp_variable = Num::alloc(cs, Some(E::Fr::one()))?;
        circuit_rescue_hash(cs, &[temp_variable])?; // Just to standardize the proof format

        let mut prices_in_batch = vec![];
        let num_prices_batch = self.signed_prices_batch.len();
        for i in 0..num_prices_batch {
            assert_eq!(self.signed_prices_batch[i].len(), NUM_PRICES);
            let signed_prices = self.signed_prices_batch[i]
                .iter()
                .map(|ps| {
                    AllocatedSignedPrice::<E, NUM_SIGNATURES_TO_VERIFY>::from_witness(
                        cs,
                        ps.clone(),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            prices_in_batch.push(signed_prices);
        }
        let guardians = self
            .guardians
            .into_iter()
            .map(|a| Address::from_address_witness(cs, &a))
            .collect::<Result<Vec<_>, _>>()?;

        // Check signatures
        let mut signatures_valid = Boolean::constant(true);
        for prices in prices_in_batch.iter() {
            for i in 0..NUM_SIGNATURES_TO_VERIFY {
                let is_current_valid = prices[i].check_by_addresses(cs, &guardians)?;
                signatures_valid = Boolean::and(cs, &signatures_valid, &is_current_valid)?;
            }
        }

        // Check if timestamp is increasing
        let last_publish_time = UInt64::zero().into_num();
        let mut is_publish_time_increasing = Boolean::constant(true);
        let mut prices_commitments = vec![];
        for i in 0..num_prices_batch {
            let publish_time = {
                // Follow what pyth does
                let mut publish_time = [Byte::zero(); 8];
                let significant_bytes = prices_in_batch[i][0].timestamp();
                publish_time[8 - significant_bytes.len()..].copy_from_slice(&significant_bytes);
                publish_time.reverse();
                UInt64::from_bytes_le(cs, &publish_time)?.into_num()
            };
            let (current_publish_time_is_equal, current_publish_time_is_greater) =
                prepacked_long_comparison(cs, &[publish_time], &[last_publish_time], &[64])?;
            let current_publish_time_is_equal_or_greater = Boolean::or(
                cs,
                &current_publish_time_is_equal,
                &current_publish_time_is_greater,
            )?;

            is_publish_time_increasing = Boolean::and(
                cs,
                &is_publish_time_increasing,
                &current_publish_time_is_equal_or_greater,
            )?;

            let mut prices_commitment_members = vec![];
            for j in 0..NUM_PRICES {
                let feed_id = {
                    // Due the limitation of zklink state tree, we can only store first 15 bytes of feed_id
                    let mut bytes = [Byte::zero(); 16];
                    bytes[1..].copy_from_slice(&prices_in_batch[i][j].feed_id()[0..15]);
                    bytes.reverse();
                    let feed_id = UInt128::from_bytes_le(cs, &bytes)?;
                    feed_id.into_num()
                };
                let price = {
                    let normalized_price_coefficient = {
                        let eighteen =
                            AllocatedNum::alloc(cs, || Ok(E::Fr::from_str("18").unwrap()))?;
                        let real_price_exponent =
                            AllocatedNum::alloc(cs, || Ok(E::Fr::from_str("8").unwrap()))?;

                        let normalized_price_exponent =
                            Num::Variable(eighteen.sub(cs, &real_price_exponent)?);
                        let mut normalized_price_exponent =
                            normalized_price_exponent.into_bits_le(cs, Some(64))?;
                        normalized_price_exponent.reverse();
                        let ten = AllocatedNum::alloc(cs, || Ok(E::Fr::from_str("10").unwrap()))?;
                        AllocatedNum::pow(cs, &ten, &normalized_price_exponent)?
                    };
                    // this price = real_price * 10^8
                    let price = prices_in_batch[i][j].price();
                    // what we want ts real_price * 10^18
                    let num = UInt256::from_be_bytes_fixed(cs, &price)?.to_num_unchecked(cs)?;
                    num.mul(cs, &Num::Variable(normalized_price_coefficient))?
                };
                prices_commitment_members.push(feed_id);
                prices_commitment_members.push(price);
            }
            let prices_commitment =
                circuit_poseidon_hash(cs, prices_commitment_members.as_slice())?;
            prices_commitments.push(prices_commitment);
        }

        Boolean::enforce_equal(cs, &is_publish_time_increasing, &Boolean::Constant(true))?;

        let mut prices_commitment_base_sum = Num::zero();
        let mut prices_commitment = Num::zero();
        let prices_num = prices_commitments.len();
        for (i, commitment) in prices_commitments.into_iter().enumerate() {
            prices_commitment_base_sum = prices_commitment_base_sum.add(cs, &commitment)?;
            let coef = E::Fr::from_str(&format!("{}", i)).unwrap();
            let x = commitment.mul(cs, &Num::Constant(coef))?;
            prices_commitment = prices_commitment.add(cs, &x)?;
        }

        let expected_prices_commitment =
            Num::alloc(cs, Some(self.public_input_data.prices_summarize.commitment))?;
        expected_prices_commitment.enforce_equal(cs, &prices_commitment)?;

        let prices_num = Num::Constant(E::Fr::from_str(&prices_num.to_string()).unwrap());

        // Compute guardian set hash
        let guardian_set_num = guardians
            .iter()
            .map(|g| g.inner().to_num_unchecked(cs))
            .collect::<Result<Vec<_>, _>>()?;
        let guardian_set_hash = circuit_poseidon_hash(cs, &guardian_set_num)?;

        let earliest_publish_time = {
            let mut earliest_publish_time = if let Some(batch) = prices_in_batch.first() {
                let mut publish_time = [Byte::zero(); 8];
                let significant_bytes = batch[0].timestamp();
                publish_time[8 - significant_bytes.len()..].copy_from_slice(&significant_bytes);
                publish_time
            } else {
                [Byte::zero(); 8]
            };
            earliest_publish_time.reverse();
            UInt64::from_bytes_le(cs, &earliest_publish_time)?.into_num()
        };
        let commitment = circuit_poseidon_hash(
            cs,
            &[
                guardian_set_hash,
                prices_commitment,
                earliest_publish_time,
                prices_num,
                prices_commitment_base_sum,
            ],
        )?;

        let expected_commitment = Num::alloc(cs, Some(self.commitment))?;
        expected_commitment.enforce_equal(cs, &commitment)?;
        expected_commitment.get_variable().inputize(cs)?;

        Ok(())
    }

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            Self::MainGate::default().into_internal(),
            Rescue5CustomGate.into_internal(), // Just to standardize the proof format
        ])
    }
}

#[cfg(test)]
mod tests {
    use advanced_circuit_component::{
        franklin_crypto::bellman::plonk::better_better_cs::cs::Circuit,
        testing::{create_test_artifacts_with_optimized_gate, Bn256},
    };

    use super::witness::{DataPackage, DataPoint};

    #[test]
    fn test_circuit() -> anyhow::Result<()> {
        let data_package = DataPackage::new(
            vec![DataPoint::new("AVAX", "36.2488073814028")],
            1705311690000,
        );
        let signature  = hex::decode("9ad1f96c083cf31f757b33b0ef6b2c4279589bf0489c1c3a7beb0005d2080dd233aaae60fdafee196362ed5b6af7498e7ba07eaa725f0bc5a041016ce54a67d61b").unwrap().try_into().unwrap();

        let mut signed_prices_batch = vec![];
        signed_prices_batch.push([[(data_package, signature)]]);

        let guardians = [hex::decode("109B4a318A4F5ddcbCA6349B45f881B4137deaFB")
            .unwrap()
            .try_into()
            .unwrap()];

        let circuit = super::PriceOracle::<Bn256, 1, 1>::new(signed_prices_batch, guardians)?;
        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        circuit.synthesize(&mut cs)?;
        println!("gate: {}", cs.n());
        Ok(())
    }
}
