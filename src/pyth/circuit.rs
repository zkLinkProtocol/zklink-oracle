use std::ops::Mul as _;

use advanced_circuit_component::franklin_crypto::bellman::pairing::{
    ff::{Field, PrimeField},
    Engine,
};
use advanced_circuit_component::{
    circuit_structures::byte::Byte,
    franklin_crypto::{
        bellman::{
            plonk::better_better_cs::cs::{Circuit, ConstraintSystem},
            SynthesisError,
        },
        plonk::circuit::{
            allocated_num::{AllocatedNum, Num},
            boolean::Boolean,
        },
    },
    glue::prepacked_long_comparison,
    vm::primitives::{UInt128, UInt32, UInt64},
};
use base64::Engine as _;
use num_bigint::BigUint;
use pythnet_sdk::{
    messages::Message,
    wire::{from_slice, v1::AccumulatorUpdateData},
};
use secp256k1::{ecdsa::RecoveryId, Secp256k1};
use serde::{Deserialize, Serialize};
use serde_wormhole::RawMessage;
use sha3::{Digest, Keccak256};
use wormhole_sdk::vaa::{Body, Header};

use crate::{
    gadgets::{
        ethereum::Address,
        poseidon::{circuit_poseidon_hash, poseidon_hash},
    },
    pyth::{PriceUpdate, PriceUpdates, Vaa},
    utils::{fr_from_biguint, new_synthesis_error},
    witness::{PricesSummarize, PublicInputData},
};

pub use pythnet_sdk;

use crate::franklin_crypto::bellman::plonk::better_better_cs::cs::{Gate, GateInternal};
use crate::franklin_crypto::plonk::circuit::custom_rescue_gate::Rescue5CustomGate;
use crate::gadgets::rescue::circuit_rescue_hash;
pub use advanced_circuit_component::franklin_crypto;
use crate::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PriceOracle<E: Engine, const NUM_PRICES: usize> {
    pub accumulator_update_data: Vec<AccumulatorUpdateData>,
    pub guardian_set: Vec<[u8; 20]>,
    pub public_input_data: PublicInputData<E>,
    pub commitment: E::Fr,
    pub num_signature_to_verify: usize,
}

impl<E: Engine, const NUM_PRICES: usize> PriceOracle<E, NUM_PRICES> {
    pub fn new(
        accumulator_update_data: Vec<AccumulatorUpdateData>,
        guardian_set: Vec<[u8; 20]>,
        num_signature_to_verify: usize,
    ) -> Result<Self, anyhow::Error> {
        let mut last_publish_time = 0;
        let mut earliest_publish_time = 0;
        let mut prices_commitments = vec![];

        let secp = Secp256k1::new();
        for data in accumulator_update_data.clone().into_iter() {
            let pythnet_sdk::wire::v1::Proof::WormholeMerkle { vaa, updates } = data.proof;
            if updates.len() != NUM_PRICES {
                anyhow::bail!("expected {} prices, got {}", NUM_PRICES, updates.len())
            }
            let vaa: wormhole_sdk::Vaa<&serde_wormhole::RawMessage> =
                serde_wormhole::from_slice(vaa.as_ref())?;
            // Check signatures in VAA
            {
                let (header, body): (Header, Body<&RawMessage>) = vaa.clone().into();
                let digest = body.digest()?;
                if header.signatures.len() < num_signature_to_verify {
                    anyhow::bail!(
                        "got {} signatures which is less than {}",
                        header.signatures.len(),
                        num_signature_to_verify
                    )
                }
                for i in 0..num_signature_to_verify {
                    let signature = header.signatures[i];
                    let recid = RecoveryId::from_i32(signature.signature[64].into())?;
                    let pubkey: &[u8; 65] = &secp
                        .recover_ecdsa(
                            &secp256k1::Message::from_digest_slice(&digest.secp256k_hash)?,
                            &secp256k1::ecdsa::RecoverableSignature::from_compact(
                                &signature.signature[..64],
                                recid,
                            )?,
                        )?
                        .serialize_uncompressed();
                    let address: [u8; 32] =
                        Keccak256::new_with_prefix(&pubkey[1..]).finalize().into();
                    let address: [u8; 20] = address[address.len() - 20..].try_into()?;
                    let found = guardian_set.iter().any(|g| g == &address);
                    if !found {
                        anyhow::bail!("invalid signature {}", hex::encode(signature.signature));
                    }
                }
            }
            // Compute price root
            let mut price_feeds = vec![];
            for price_update in updates {
                let message: Vec<u8> = price_update.message.clone().into();
                if let Message::PriceFeedMessage(price_feed) =
                    from_slice::<byteorder::BE, Message>(&message)?
                {
                    price_feeds.push(price_feed);
                } else {
                    anyhow::bail!("invalid price feed message")
                };
            }
            {
                let mut prices_commitment_members = vec![];
                for price_feed in price_feeds.iter() {
                    let feed_id = {
                        // Due the limitation of zklink state tree, we can only store first 15 bytes of feed_id
                        let mut bytes = [0u8; 16];
                        bytes[1..].copy_from_slice(&price_feed.feed_id[0..15]);
                        BigUint::from_bytes_be(&bytes)
                    };
                    // normalized_price = 10^(18-real_exponent) * price
                    let price = {
                        let exponent = (18 + price_feed.exponent) as u32;
                        let coefficient = BigUint::from(10u32).pow(exponent);
                        coefficient.mul(&BigUint::try_from(price_feed.price)?)
                    };
                    prices_commitment_members.push(fr_from_biguint::<E>(&feed_id)?);
                    prices_commitment_members.push(fr_from_biguint::<E>(&price)?);
                }
                let prices_commitment = poseidon_hash::<E>(&prices_commitment_members);
                prices_commitments.push(prices_commitment);
            }
            // Check publish time is increasing
            {
                if price_feeds[0].publish_time < last_publish_time {
                    anyhow::bail!(
                        "publish time is not increasing: {} <= {}",
                        price_feeds[0].price,
                        last_publish_time
                    )
                };
                last_publish_time = price_feeds[0].publish_time;
                if earliest_publish_time == 0 {
                    earliest_publish_time = last_publish_time;
                }
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

        let earliest_publish_time =
            fr_from_biguint::<E>(&BigUint::from(earliest_publish_time as u64))?;

        let mut prices_num = E::Fr::zero();
        let mut prices_commitment_base_sum = E::Fr::zero();
        let mut prices_commitment = E::Fr::zero();
        for mut commitment in prices_commitments.into_iter() {
            Field::add_assign(&mut prices_commitment_base_sum, &commitment);
            Field::add_assign(&mut prices_num, &E::Fr::one());
            Field::mul_assign(&mut commitment, &prices_num);
            Field::add_assign(&mut prices_commitment, &commitment);
        }

        let commitment = poseidon_hash::<E>(&[
            guardian_set_hash,
            earliest_publish_time,
            prices_commitment,
            prices_num,
            prices_commitment_base_sum,
        ]);

        Ok(Self {
            accumulator_update_data,
            guardian_set,
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
            num_signature_to_verify,
        })
    }

    pub fn circuit_default(
        num_accumulator_update_dara: usize,
        num_signature_to_verify: usize,
    ) -> Self {
        let accumulator_update_data = {
            // base64 encoded hex from hermes API /api/latest_vaas (https://hermes.pyth.network/docs/#/rest/latest_vaas)
            let hex = "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";
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(hex)
                .unwrap();
            AccumulatorUpdateData::try_from_slice(bytes.as_ref()).unwrap()
        };
        let accumulator_update_data = (0..num_accumulator_update_dara)
            .map(|_| accumulator_update_data.clone())
            .collect::<Vec<_>>();

        let guardian_set = vec![
            "58CC3AE5C097b213cE3c81979e1B9f9570746AA5",
            "fF6CB952589BDE862c25Ef4392132fb9D4A42157",
            "114De8460193bdf3A2fCf81f86a09765F4762fD1",
            "107A0086b32d7A0977926A205131d8731D39cbEB",
            "8C82B2fd82FaeD2711d59AF0F2499D16e726f6b2",
            "11b39756C042441BE6D8650b69b54EbE715E2343",
            "54Ce5B4D348fb74B958e8966e2ec3dBd4958a7cd",
            "15e7cAF07C4e3DC8e7C469f92C8Cd88FB8005a20",
            "74a3bf913953D695260D88BC1aA25A4eeE363ef0",
            "000aC0076727b35FBea2dAc28fEE5cCB0fEA768e",
            "AF45Ced136b9D9e24903464AE889F5C8a723FC14",
            "f93124b7c738843CBB89E864c862c38cddCccF95",
            "D2CC37A4dc036a8D232b48f62cDD4731412f4890",
            "DA798F6896A3331F64b48c12D1D57Fd9cbe70811",
            "71AA1BE1D36CaFE3867910F99C09e347899C19C3",
            "8192b6E7387CCd768277c17DAb1b7a5027c0b3Cf",
            "178e21ad2E77AE06711549CFBB1f9c7a9d8096e8",
            "5E1487F35515d02A92753504a8D75471b9f49EdB",
            "6FbEBc898F403E4773E95feB15E80C9A99c8348d",
        ]
        .iter()
        .map(|guardian| hex::decode(guardian).unwrap().try_into().unwrap())
        .collect();
        Self::new(
            accumulator_update_data,
            guardian_set,
            num_signature_to_verify,
        )
        .unwrap()
    }

    pub fn public_input_data(&self) -> PublicInputData<E> {
        self.public_input_data.clone()
    }

    pub fn verification_num(&self) -> usize {
        self.accumulator_update_data.len()
    }
}

impl<E: Engine, const NUM_PRICES: usize> Circuit<E> for PriceOracle<E, NUM_PRICES> {
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        crate::utils::add_bitwise_logic_and_range_table(cs)?;
        let temp_variable = Num::alloc(cs, Some(E::Fr::one()))?;
        circuit_rescue_hash(cs, &[temp_variable])?; // Just to standardize the proof format

        let guardian_set = self
            .guardian_set
            .iter()
            .map(|w| Address::from_address_witness(cs, w))
            .collect::<Result<Vec<_>, _>>()?;
        let mut price_updates_batch = vec![];
        // Construct circuit variable from witness
        for accumulator_update_data in self.accumulator_update_data.clone() {
            let pythnet_sdk::wire::v1::Proof::WormholeMerkle { vaa, updates } =
                accumulator_update_data.proof;
            let vaa = {
                let vaa: wormhole_sdk::Vaa<&serde_wormhole::RawMessage> =
                    serde_wormhole::from_slice(vaa.as_ref()).unwrap();
                Vaa::<_>::from_vaa_witness(cs, vaa, self.num_signature_to_verify)?
            };
            let price_updates: [_; NUM_PRICES] = {
                let updates = updates
                    .into_iter()
                    .map(|u| PriceUpdate::<_>::from_price_update_witness(cs, u))
                    .collect::<Result<Vec<_>, _>>()?;
                let len = updates.len();
                updates.try_into().map_err(|_| {
                    new_synthesis_error(format!("expected {} prices, got {}", NUM_PRICES, len))
                })?
            };
            price_updates_batch.push(PriceUpdates { vaa, price_updates });
        }

        let last_publish_time = UInt64::zero().into_num();
        let mut is_publish_time_increasing = Boolean::constant(true);
        let mut prices_commitments = vec![];
        for price_updates in price_updates_batch.iter() {
            // Check signatures in VAA
            {
                let is_valid = price_updates.check_by_address(cs, &guardian_set)?;
                Boolean::enforce_equal(cs, &is_valid, &Boolean::Constant(true))?;
            }
            // Compute price root
            {
                let mut prices_commitment_members = vec![];
                for price_update in price_updates.price_updates {
                    let price_feed = price_update.message;
                    let feed_id = {
                        // Due the limitation of zklink state tree, we can only store first 15 bytes of feed_id
                        let mut bytes = [Byte::zero(); 16];
                        bytes[1..].copy_from_slice(&price_feed.feed_id[0..15]);
                        bytes.reverse();
                        let feed_id = UInt128::from_bytes_le(cs, &bytes)?;
                        feed_id.into_num()
                    };
                    let price = {
                        // real exponent = 2^32 - exponent value in be_bytes (complement format)
                        // normalized_price = 10^(18-real_exponent) * price
                        let power_32_of_2 = {
                            let two = {
                                let one = AllocatedNum::one(cs);
                                one.add(cs, &one)?
                            };
                            let exp = vec![
                                Boolean::constant(true),  // 32
                                Boolean::constant(false), // 16
                                Boolean::constant(false), // 8
                                Boolean::constant(false), // 4
                                Boolean::constant(false), // 2
                                Boolean::constant(false), // 1
                            ];
                            AllocatedNum::pow(cs, &two, exp)?
                        };
                        let price_exponent = {
                            let mut price_exponent = price_feed.exponent;
                            price_exponent.reverse();
                            UInt32::from_bytes_le(cs, &price_exponent)?.into_num()
                        };
                        // for complement number, the real absolute value = 2^32 - complement value
                        let absolute_price_exponent =
                            power_32_of_2.sub(cs, &price_exponent.get_variable())?;
                        let normalized_price_coefficient = {
                            let eighteen =
                                AllocatedNum::alloc(cs, || Ok(E::Fr::from_str("18").unwrap()))?;
                            let normalized_price_exponent =
                                Num::Variable(eighteen.sub(cs, &absolute_price_exponent)?);
                            let mut normalized_price_exponent =
                                normalized_price_exponent.into_bits_le(cs, Some(64))?;
                            normalized_price_exponent.reverse();
                            let ten =
                                AllocatedNum::alloc(cs, || Ok(E::Fr::from_str("10").unwrap()))?;
                            AllocatedNum::pow(cs, &ten, &normalized_price_exponent)?
                        };
                        let mut price = price_feed.price;
                        price.reverse();
                        let num = UInt64::from_bytes_le(cs, &price)?.into_num();
                        num.mul(cs, &Num::Variable(normalized_price_coefficient))?
                    };
                    prices_commitment_members.push(feed_id);
                    prices_commitment_members.push(price);
                }
                let prices_commitment =
                    circuit_poseidon_hash(cs, prices_commitment_members.as_slice())?;
                prices_commitments.push(prices_commitment);
            }
            // Check publish time is increasing
            {
                let publish_time = {
                    let mut publish_time = price_updates.price_updates[0].message.publish_time;
                    publish_time.reverse();
                    UInt64::from_bytes_le(cs, &publish_time)?.into_num()
                };
                let (current_publish_time_is_equal, current_publish_time_is_greater) =
                    prepacked_long_comparison(cs, &[publish_time], &[last_publish_time], &[8 * 8])?;
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
            }
        }

        Boolean::enforce_equal(cs, &is_publish_time_increasing, &Boolean::Constant(true))?;

        let mut prices_commitment_base_sum = Num::zero();
        let mut prices_commitment = Num::zero();
        let mut prices_num = Num::zero();
        for commitment in prices_commitments.into_iter() {
            prices_commitment_base_sum = prices_commitment_base_sum.add(cs, &commitment)?;
            prices_num = prices_num.add(cs, &Num::one())?;
            let appended = commitment.mul(cs, &prices_num)?;
            prices_commitment = prices_commitment.add(cs, &appended)?;
        }

        {
            let expected_prices_commitment =
                Num::alloc(cs, Some(self.public_input_data.prices_summarize.commitment))?;
            expected_prices_commitment.enforce_equal(cs, &prices_commitment)?;
        }

        // Compute guardian set hash
        let guardian_set_num = guardian_set
            .iter()
            .map(|g| g.inner().to_num_unchecked(cs))
            .collect::<Result<Vec<_>, _>>()?;
        let guardian_set_hash = circuit_poseidon_hash(cs, &guardian_set_num)?;

        let earliest_publish_time = {
            let mut earliest_publish_time = if let Some(batch) = price_updates_batch.first() {
                batch.price_updates[0].message.publish_time
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
                earliest_publish_time,
                prices_commitment,
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

// Gates of the circuit for the 13 signatures and 4 prices
pub const GATES: usize = 13275521;

/// Returns the maximum number of VAA (13 signatures + 4 prices) that can be verified by the circuit.
pub fn max_vaa(power_of_tau: usize) -> usize {
    let base = 2usize;
    base.pow(power_of_tau as u32) / GATES
}

#[cfg(test)]
mod tests {
    use super::PriceOracle;
    use advanced_circuit_component::franklin_crypto::bellman::pairing::bn256::Bn256;
    use advanced_circuit_component::franklin_crypto::bellman::plonk::better_better_cs::cs::Circuit;
    use advanced_circuit_component::testing::create_test_artifacts_with_optimized_gate;
    use base64::Engine as _;
    use pythnet_sdk::wire::v1::AccumulatorUpdateData;

    #[test]
    fn test_price_oracle() -> Result<(), anyhow::Error> {
        let accumulator_update_data = {
            // base64 encoded hex from hermes API /api/latest_vaas (https://hermes.pyth.network/docs/#/rest/latest_vaas)
            let hex = "UE5BVQEAAAADuAEAAAADDQKR8EO5PyxuSK5T+gNQkaJreUwBZifEwzHpa9tpHugiM09aJtlNZ+QGacbggPbh74MLGekxLbW0L3nW0iWvpp9VAQP7Qvjz7AWngPgTQkXph4sWBNxZ//lLN1TmuddxZ85wFQqdpbC2mX8VAhRL7sER5oFsFWLzxQ1HBLWrHACe2ekWAQTz+pimoBD55XdYKhtbb4/0T01HYaHDJbL0yLgz5UTmy2DxgkEYW0AqiQeQq5kT7wwgaiS/1R2MqVHv4kKBBy4qAAZ4POFVBLBb7HktrrqZCazVQkXRX1h92E23BXK3Vjt+Sxf/ueIJJXK6PoQJKpNuGRPLJPu55O5CCeFga/4kihOZAAfmHbBMH2IiDqUxccAigMYDwFhuMN3Zjby/UiQwcccKnl1tyB6PZUjTBrz9huv+3Lb37TYZH3GLXvwPgGuy+oI2AQjiUQNmxfe/ns3lYELUcJmD0SjfC9O9t757mkWdMZyXzHULb4Z17xaBW9b0CDvKMf+gh6qqHmwBOokmNEP2Ln/WAAo+m7ccVx/M7EkPu5PXFnQt11+mixtm8/gzAXn8TR+/Ng9l/2Gx/T6iXYNgL2ErXIXiGDXxFjnUa08FcaKLgmuvAAvH0mXgEHynf85669H4swCIWlRucdhFxmMp/W9mihoeFQgXbypikATYOzLI0NV3oOCtj6ASvGecSfa4FngwkxqvAAzzY2hcw9bh2u/NU31oC9TRmon9QxkKWNLm3B6gyGVxJFurQ5kfLPHJ9JfAll/oVPlTe2PDzC9z0/Ea2vuPcB1IAQ2Xgc8lPA5CZYuY2U5rGAPUT2nov1d4aFZGDunWdte8uXISM5UEOYaENGKUkuCQn9CdXPL+nvD3nD/LPtDG+gjuAQ6+q5Uzyq307xHErRAcoVkYziIPSoGZf6Rgh0ted5pZokh5P1kzWBsJHM3ISzW3IX4slBfZweZQLMCIpcBTFR/BABD9FzYKBnUQrmi+yZIJpGNQZmxNXVQAybg8qTayhVPOGAFvQ8boVEysxiUlqLKTmI05FpmrB9ESrZMR/Fa1ULUJARL2cMOlIJ9lz4NuPdZAWyp5OONMXZtDI1nRLCMlqwXA7ApUrzUEX8vz6JTbkhEf3a0vh4EvTlv3vTRuYk3Lg6mwAGW4etIAAAAAABrhAfrtrFhR4yubI7X5QRqMK6xKrj7U3XuBHdGnLqSqcQAAAAACSzpwAUFVV1YAAAAAAAdTH/EAACcQjEIPxn/xQVV6+Fv/qiA+BGAg0v0DAFUA5i32yLSoX+GmfbRNwS3l2zMPesZrctxliv7fD0pBW0MAAAPz0SN1oAAAAABtfK+i////+AAAAABluHrSAAAAAGW4etIAAAP04O+QYAAAAABtDW3CCsxZy9+gP6FGv8mbQmMYDxz4+o9Rxgu21d4qn2QTywSAEhTyQV4Vk62iNhMB1q9Ft+zNlQa3YI7malhS5QAyq4GasWRs5jKCGD8ZH2kz65W5xL13Ok08Sxltd0uQALfhNZoUmBQQwV0jW2zRZG61XI3NLLLtWSgb1NU5YXCDZNJ+F/YHeR73m6B2st6PmXoYDyav5RjB3YtDus4ERhQ61M6CAc0bSRGmF0RCSEssboaitjoxdfw3XEl9SH3PZGFwZ282DprCaLI7AFUA5i32yLSoX+GmfbRNwS3l2zMPesZrctxliv7fD0pBW0MAAAPz0SN1oAAAAABtfK+i////+AAAAABluHrSAAAAAGW4etIAAAP04O+QYAAAAABtDW3CCsxZy9+gP6FGv8mbQmMYDxz4+o9Rxgu21d4qn2QTywSAEhTyQV4Vk62iNhMB1q9Ft+zNlQa3YI7malhS5QAyq4GasWRs5jKCGD8ZH2kz65W5xL13Ok08Sxltd0uQALfhNZoUmBQQwV0jW2zRZG61XI3NLLLtWSgb1NU5YXCDZNJ+F/YHeR73m6B2st6PmXoYDyav5RjB3YtDus4ERhQ61M6CAc0bSRGmF0RCSEssboaitjoxdfw3XEl9SH3PZGFwZ282DprCaLI7AFUA5i32yLSoX+GmfbRNwS3l2zMPesZrctxliv7fD0pBW0MAAAPz0SN1oAAAAABtfK+i////+AAAAABluHrSAAAAAGW4etIAAAP04O+QYAAAAABtDW3CCsxZy9+gP6FGv8mbQmMYDxz4+o9Rxgu21d4qn2QTywSAEhTyQV4Vk62iNhMB1q9Ft+zNlQa3YI7malhS5QAyq4GasWRs5jKCGD8ZH2kz65W5xL13Ok08Sxltd0uQALfhNZoUmBQQwV0jW2zRZG61XI3NLLLtWSgb1NU5YXCDZNJ+F/YHeR73m6B2st6PmXoYDyav5RjB3YtDus4ERhQ61M6CAc0bSRGmF0RCSEssboaitjoxdfw3XEl9SH3PZGFwZ282DprCaLI7";
            let bytes = base64::engine::general_purpose::STANDARD.decode(hex)?;
            AccumulatorUpdateData::try_from_slice(bytes.as_ref())?
        };
        let guardian_set = vec![
            "58CC3AE5C097b213cE3c81979e1B9f9570746AA5",
            "fF6CB952589BDE862c25Ef4392132fb9D4A42157",
            "114De8460193bdf3A2fCf81f86a09765F4762fD1",
            "107A0086b32d7A0977926A205131d8731D39cbEB",
            "8C82B2fd82FaeD2711d59AF0F2499D16e726f6b2",
            "11b39756C042441BE6D8650b69b54EbE715E2343",
            "54Ce5B4D348fb74B958e8966e2ec3dBd4958a7cd",
            "15e7cAF07C4e3DC8e7C469f92C8Cd88FB8005a20",
            "74a3bf913953D695260D88BC1aA25A4eeE363ef0",
            "000aC0076727b35FBea2dAc28fEE5cCB0fEA768e",
            "AF45Ced136b9D9e24903464AE889F5C8a723FC14",
            "f93124b7c738843CBB89E864c862c38cddCccF95",
            "D2CC37A4dc036a8D232b48f62cDD4731412f4890",
            "DA798F6896A3331F64b48c12D1D57Fd9cbe70811",
            "71AA1BE1D36CaFE3867910F99C09e347899C19C3",
            "8192b6E7387CCd768277c17DAb1b7a5027c0b3Cf",
            "178e21ad2E77AE06711549CFBB1f9c7a9d8096e8",
            "5E1487F35515d02A92753504a8D75471b9f49EdB",
            "6FbEBc898F403E4773E95feB15E80C9A99c8348d",
        ]
        .iter()
        .map(|guardian| hex::decode(guardian).unwrap().try_into().unwrap())
        .collect();
        let price_oracle = PriceOracle::<Bn256, 3>::new(
            vec![accumulator_update_data.clone(), accumulator_update_data],
            guardian_set,
            1,
        )?;
        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        price_oracle.synthesize(&mut cs)?;
        assert!(cs.is_satisfied());
        println!("circuit contains {} gates", cs.n());
        Ok(())
    }
}
