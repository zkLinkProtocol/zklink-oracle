use std::ops::Mul as _;

use num_bigint::BigUint;
use pairing::{
    ff::{Field, PrimeField},
    Engine,
};
use pythnet_sdk::{
    messages::Message,
    wire::{from_slice, v1::AccumulatorUpdateData},
};
use secp256k1::{ecdsa::RecoveryId, Secp256k1};
use serde::{Deserialize, Serialize};
use serde_wormhole::RawMessage;
use sha3::{Digest, Keccak256};
use sync_vm::{
    circuit_structures::byte::Byte,
    franklin_crypto::{
        bellman::{
            plonk::better_better_cs::cs::{Circuit, ConstraintSystem, Width4MainGateWithDNext},
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
use wormhole_sdk::vaa::{Body, Header};

use crate::{
    gadgets::{
        ethereum::Address,
        poseidon::{circuit_poseidon_hash, poseidon_hash},
    },
    pyth::{PriceUpdate, PriceUpdates, Vaa},
    utils::new_synthesis_error,
};

pub use pythnet_sdk;

pub mod gadgets;
pub mod pyth;
pub mod utils;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkLinkOracle<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICE: usize> {
    pub accumulator_update_data: Vec<AccumulatorUpdateData>,
    pub guardian_set: Vec<[u8; 20]>,
    pub prices_commitment: E::Fr,
    pub commitment: E::Fr,
}

impl<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICES: usize>
    ZkLinkOracle<E, NUM_SIGNATURES_TO_VERIFY, NUM_PRICES>
{
    pub fn new(
        accumulator_update_data: Vec<AccumulatorUpdateData>,
        guardian_set: Vec<[u8; 20]>,
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
                serde_wormhole::from_slice(&vaa.as_ref())?;
            // Check signatures in VAA
            {
                let (header, body): (Header, Body<&RawMessage>) = vaa.clone().into();
                let digest = body.digest()?;
                if header.signatures.len() < NUM_SIGNATURES_TO_VERIFY {
                    anyhow::bail!(
                        "got {} signatures which is less than {}",
                        header.signatures.len(),
                        NUM_SIGNATURES_TO_VERIFY
                    )
                }
                for signature in header.signatures {
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
                    let found = guardian_set.iter().find(|g| g == &&address).is_some();
                    if !found {
                        anyhow::bail!("invalid signature {}", hex::encode(&signature.signature));
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
                        let coefficient = BigUint::from(10 as u32).pow(exponent);
                        coefficient.mul(&BigUint::try_from(price_feed.price)?)
                    };
                    prices_commitment_members.push(fr_from_biguint::<E>(&feed_id)?);
                    prices_commitment_members.push(fr_from_biguint::<E>(&price)?);
                }
                let prices_commitment = poseidon_hash::<E>(&prices_commitment_members)[0];
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
            poseidon_hash::<E>(&input)[0]
        };

        let earliest_publish_time =
            fr_from_biguint::<E>(&BigUint::from(earliest_publish_time as u64))?;

        let prices_commitment =
            prices_commitments
                .into_iter()
                .fold(<E::Fr as Field>::zero(), |mut acc, x| {
                    Field::square(&mut acc);
                    Field::add_assign(&mut acc, &x);
                    acc
                });
        let commitment =
            poseidon_hash::<E>(&[guardian_set_hash, prices_commitment, earliest_publish_time])[0];
        Ok(Self {
            accumulator_update_data,
            guardian_set,
            prices_commitment,
            commitment,
        })
    }
}

fn fr_from_biguint<E: Engine>(biguint: &BigUint) -> Result<E::Fr, SynthesisError> {
    let biguint = biguint.to_str_radix(10);
    E::Fr::from_str(&biguint).ok_or_else(|| {
        new_synthesis_error(format!(
            "failed to convert old_prices_commitment {} to field element",
            biguint
        ))
    })
}

impl<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICES: usize> Circuit<E>
    for ZkLinkOracle<E, NUM_SIGNATURES_TO_VERIFY, NUM_PRICES>
{
    type MainGate = Width4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let guardian_set = self
            .guardian_set
            .iter()
            .map(|w| Address::from_address_wtiness(cs, w))
            .collect::<Result<Vec<_>, _>>()?;
        let mut price_updates_batch = vec![];
        // Construct circuit variable from witness
        for accumulator_update_data in self.accumulator_update_data.clone() {
            let pythnet_sdk::wire::v1::Proof::WormholeMerkle { vaa, updates } =
                accumulator_update_data.proof;
            let vaa = {
                let vaa: wormhole_sdk::Vaa<&serde_wormhole::RawMessage> =
                    serde_wormhole::from_slice(&vaa.as_ref()).unwrap();
                Vaa::<_, NUM_SIGNATURES_TO_VERIFY>::from_vaa_witness(cs, vaa)?
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
                        let normalized_price =
                            num.mul(cs, &Num::Variable(normalized_price_coefficient))?;
                        normalized_price
                    };
                    prices_commitment_members.push(feed_id);
                    prices_commitment_members.push(price);
                }
                let prices_commitment =
                    circuit_poseidon_hash(cs, prices_commitment_members.as_slice())?[0];
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
            }
        }

        let prices_commitment =
            prices_commitments
                .into_iter()
                .fold(Ok(Num::<E>::zero()), |acc, x| {
                    let acc = acc?;
                    let square = acc.mul(cs, &acc)?;
                    square.add(cs, &x)
                })?;
        let expected_prices_commitment = {
            let n = AllocatedNum::alloc_input(cs, || Ok(self.prices_commitment))?;
            Num::Variable(n)
        };
        expected_prices_commitment.enforce_equal(cs, &prices_commitment)?;

        Boolean::enforce_equal(cs, &is_publish_time_increasing, &Boolean::Constant(true))?;

        // Compute guardian set hash
        let guardian_set_num = guardian_set
            .iter()
            .map(|g| g.inner().to_num_unchecked(cs))
            .collect::<Result<Vec<_>, _>>()?;
        let guardian_set_hash = circuit_poseidon_hash(cs, &guardian_set_num)?[0];

        let earliest_publish_time = {
            let mut earliest_publish_time =
                price_updates_batch[0].price_updates[0].message.publish_time;
            earliest_publish_time.reverse();
            UInt64::from_bytes_le(cs, &earliest_publish_time)?.into_num()
        };
        let commitment = circuit_poseidon_hash(
            cs,
            &[guardian_set_hash, prices_commitment, earliest_publish_time],
        )?[0];

        let expected_commitment = {
            // Make commitment public input
            let n = AllocatedNum::alloc_input(cs, || Ok(self.commitment))?;
            Num::Variable(n)
        };
        expected_commitment.enforce_equal(cs, &commitment)?;
        Ok(())
    }
}

// Gates of the circuit for the 13 signatures and 4 prices
pub const GATES: usize = 13275521;

/// Returns the maximum number of VAA (13 signatures + 4 prices) that can be verified by the circuit.
pub fn max_vaa(power_of_tau: usize) -> usize {
    let base = 2 as usize;
    base.pow(power_of_tau as u32) / GATES
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use pairing::bn256::Bn256;
    use pythnet_sdk::wire::v1::AccumulatorUpdateData;
    use sync_vm::franklin_crypto::bellman::plonk::better_better_cs::cs::Circuit;

    use crate::{utils::testing::create_test_constraint_system, ZkLinkOracle};

    #[test]
    fn test_zklink_oracle() -> Result<(), anyhow::Error> {
        let accumulator_update_data = {
            // base64 encoded hex from hermes API /api/latest_vaas (https://hermes.pyth.network/docs/#/rest/latest_vaas)
            let hex = "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";
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
        let zklink_oracle = ZkLinkOracle::<Bn256, 1, 4>::new(
            vec![accumulator_update_data.clone(), accumulator_update_data],
            guardian_set,
        )?;
        let cs = &mut create_test_constraint_system()?;
        zklink_oracle.synthesize(cs)?;
        println!("circuit contains {} gates", cs.n());
        Ok(())
    }
}
