use base64::Engine as _;
use pairing::{
    ff::{Field, PrimeField, ScalarEngine},
    Engine,
};
use pythnet_sdk::wire::v1::AccumulatorUpdateData;
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

use crate::{
    gadgets::{ethereum::Address, poseidon::circuit_poseidon_hash},
    pyth::{PriceUpdate, PriceUpdates, Vaa},
    utils::new_synthesis_error,
};

pub mod gadgets;
pub mod pyth;
pub mod utils;

pub struct ZkLinkOracle<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICE: usize> {
    pub accumulator_update_data: Vec<AccumulatorUpdateData>,
    pub guardian_set: [[u8; 20]; 19], // Wormhole has 19 Guardians
    pub old_prices_root: E::Fr,
    pub commitment: E::Fr,
}

impl<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICE: usize> Default
    for ZkLinkOracle<E, NUM_SIGNATURES_TO_VERIFY, NUM_PRICE>
{
    fn default() -> Self {
        let accumulator_update_data = {
            // base64 encoded hex from hermes API /api/latest_vaas (https://hermes.pyth.network/docs/#/rest/latest_vaas)
            let hex = "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";
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(hex)
                .unwrap();
            AccumulatorUpdateData::try_from_slice(bytes.as_ref()).unwrap()
        };
        let guardian_set = [
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
        .map(|guardian| hex::decode(guardian).unwrap().try_into().unwrap());
        Self {
            accumulator_update_data: vec![accumulator_update_data],
            guardian_set,
            old_prices_root: <<E as ScalarEngine>::Fr as Field>::zero(),
            commitment: <<E as ScalarEngine>::Fr as PrimeField>::from_str(
                "14282269052574546871186012787549977474958928608190269975251250759954740304151",
            )
            .unwrap(),
        }
    }
}

impl<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICES: usize> Circuit<E>
    for ZkLinkOracle<E, NUM_SIGNATURES_TO_VERIFY, NUM_PRICES>
{
    type MainGate = Width4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let mut prices_commitment = Num::alloc(cs, Some(self.old_prices_root))?;
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
        let mut prices_commitment_members = vec![prices_commitment];
        for price_updates in price_updates_batch.iter() {
            // Check signatures in VAA
            {
                let is_valid = price_updates.check_by_address(cs, &guardian_set)?;
                Boolean::enforce_equal(cs, &is_valid, &Boolean::Constant(true))?;
            }
            // Compute price root
            {
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
                                Boolean::constant(false), // 1
                                Boolean::constant(false), // 2
                                Boolean::constant(false), // 4
                                Boolean::constant(false), // 8
                                Boolean::constant(false), // 16
                                Boolean::constant(true),  // 32
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
                            let normalized_price_exponent =
                                normalized_price_exponent.into_bits_le(cs, Some(64))?;
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
            }
            // Check publish time is increasing
            {
                let publish_time = {
                    let mut publish_time = price_updates.price_updates[0].message.publish_time;
                    publish_time.reverse();
                    UInt64::from_bytes_le(cs, &publish_time)?.into_num()
                };
                let (_, current_publish_time_is_greater) =
                    prepacked_long_comparison(cs, &[publish_time], &[last_publish_time], &[32])?;
                is_publish_time_increasing = Boolean::and(
                    cs,
                    &is_publish_time_increasing,
                    &current_publish_time_is_greater,
                )?;
            }
        }
        prices_commitment = circuit_poseidon_hash(cs, prices_commitment_members.as_slice())?[0];
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

#[cfg(test)]
mod tests {
    use pairing::bn256::Bn256;
    use sync_vm::franklin_crypto::bellman::{plonk::better_better_cs::cs::Circuit, SynthesisError};

    use crate::{utils::testing::create_test_constraint_system, ZkLinkOracle};

    #[test]
    fn test_zklink_oracle() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let zklink_oracle = ZkLinkOracle::<Bn256, 1, 4>::default();
        zklink_oracle.synthesize(cs)?;
        println!("circuit contains {} gates", cs.n());
        Ok(())
    }
}
