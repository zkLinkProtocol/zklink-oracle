use num_bigint::BigUint;
use pairing::{
    ff::{Field, PrimeField},
    Engine,
};
use sync_vm::{
    circuit_structures::byte::Byte,
    franklin_crypto::{
        bellman::{
            plonk::better_better_cs::{
                cs::{Circuit, ConstraintSystem},
                gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext,
            },
            SynthesisError,
        },
        plonk::circuit::{
            allocated_num::{AllocatedNum, Num},
            boolean::Boolean,
        },
    },
    glue::prepacked_long_comparison,
    vm::primitives::{uint256::UInt256, UInt128, UInt64},
};

use crate::{
    fr_from_biguint,
    gadgets::{
        ethereum::Address,
        poseidon::{circuit_poseidon_hash, poseidon_hash},
    },
    PublicInputData,
};

use self::{
    circuit::{AllocatedSignedDataPackage, AllocatedSignedPrice},
    types::DataPackage,
};

pub mod circuit;
pub mod types;

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

pub struct PriceOraclex<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICE: usize> {
    pub signed_prices_batch: Vec<[[(DataPackage, [u8; 65]); NUM_SIGNATURES_TO_VERIFY]; NUM_PRICE]>,
    pub guardians: [[u8; 20]; NUM_SIGNATURES_TO_VERIFY],
    pub public_input_data: PublicInputData<E>,
    pub commitment: E::Fr,
}

impl<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICES: usize> Circuit<E>
    for PriceOraclex<E, NUM_SIGNATURES_TO_VERIFY, NUM_PRICES>
{
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
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
            .map(|a| Address::from_address_wtiness(cs, &a))
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
                publish_time[..significant_bytes.len()].copy_from_slice(&significant_bytes);
                publish_time.reverse();
                UInt64::from_bytes_le(cs, &publish_time)?.into_num()
            };
            let (current_publish_time_is_equal, current_publish_time_is_greater) =
                prepacked_long_comparison(cs, &[publish_time], &[last_publish_time], &[32])?;
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

        let prices_commitment =
            prices_commitments
                .into_iter()
                .try_fold(Num::<E>::zero(), |acc, x| {
                    let square = acc.mul(cs, &acc)?;
                    square.add(cs, &x)
                })?;
        let expected_prices_commitment = {
            let n = AllocatedNum::alloc(cs, || Ok(self.public_input_data.prices_commitment))?;
            Num::Variable(n)
        };
        expected_prices_commitment.enforce_equal(cs, &prices_commitment)?;

        Boolean::enforce_equal(cs, &is_publish_time_increasing, &Boolean::Constant(true))?;

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
                publish_time[..significant_bytes.len()].copy_from_slice(&significant_bytes);
                publish_time
            } else {
                [Byte::zero(); 8]
            };
            earliest_publish_time.reverse();
            UInt64::from_bytes_le(cs, &earliest_publish_time)?.into_num()
        };

        let commitment = circuit_poseidon_hash(
            cs,
            &[guardian_set_hash, prices_commitment, earliest_publish_time],
        )?;

        let expected_commitment = {
            // Make commitment public input
            let n = AllocatedNum::alloc_input(cs, || Ok(self.commitment))?;
            Num::Variable(n)
        };
        expected_commitment.enforce_equal(cs, &commitment)?;

        Ok(())
    }
}
