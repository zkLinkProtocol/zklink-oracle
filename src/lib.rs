use pairing::Engine;
use pyth::{Update, Vaa};
use sync_vm::{
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::boolean::Boolean,
    },
    vm::{partitioner::smart_and, primitives::uint256::UInt256},
};

pub mod gadgets;
pub mod params;
#[allow(dead_code)]
pub mod pyth;
pub mod utils;

pub fn check_price_updates<E: Engine, CS: ConstraintSystem<E>, const N1: usize, const N2: usize>(
    cs: &mut CS,
    vaa: &Vaa<E, N2>,
    updates: &[Update<E, N1>],
    guardian_set: &[(UInt256<E>, UInt256<E>)],
) -> Result<Boolean, SynthesisError> {
    if guardian_set.len() == 0 {
        return Ok(Boolean::Constant(false));
    }
    // Verify wormhole signature
    let recovered = vaa.ecrecover(cs)?;
    let mut ecrecover_successful = vec![];
    let mut pubkeys_matched = vec![];
    for (successful, (x, y)) in recovered {
        ecrecover_successful.push(successful);
        Boolean::enforce_equal(cs, &successful, &Boolean::Constant(true))?;
        let mut matched = vec![];
        for pubkey in guardian_set {
            let x_is_equal = UInt256::equals(cs, &x, &pubkey.0)?;
            let y_is_equal = UInt256::equals(cs, &y, &pubkey.1)?;
            let is_equal = Boolean::and(cs, &x_is_equal, &y_is_equal)?;
            matched.push(is_equal);
        }
        pubkeys_matched.push(smart_and(cs, &matched)?)
    }

    // Verify pyth merkle tree
    let mut valid_updates = vec![Boolean::Constant(true); updates.len()];
    let root = vaa.merkle_root();
    let mut i = 0;
    for update in updates {
        i = i + 1;
        let check = update.check(cs, &root)?;
        valid_updates.push(check);
    }
    let result = {
        let ecrecover_successful = smart_and(cs, &ecrecover_successful)?;
        let pubkeys_matched = smart_and(cs, &pubkeys_matched)?;
        let valid_updates = smart_and(cs, &valid_updates)?;
        smart_and(cs, &[ecrecover_successful, pubkeys_matched, valid_updates])
    };
    result
}

#[cfg(test)]
mod testss {
    use base64::Engine as _;
    use pairing::Engine;
    use pythnet_sdk::wire::v1::AccumulatorUpdateData;
    use sync_vm::{
        franklin_crypto::{
            bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
            plonk::circuit::boolean::Boolean,
        },
        vm::primitives::uint256::UInt256,
    };

    use crate::{
        check_price_updates,
        params::DEEPTH_MERKLE_TREE,
        pyth,
        utils::{
            new_synthesis_error, testing::create_test_constraint_system, uint256_from_bytes_witness,
        },
    };

    #[test]
    fn test_integration() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let pubkeys = [
            "2a953a2e8b1052eb70c1d7b556b087deed598b55608396686c1c811b9796c763078687ce10459f4f25fb7a0fbf8727bb0fb51e00820e93a123f652ee843cf08d",
        ];
        let accumulator_update = {
            let hex = "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";
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(hex)
                .unwrap();
            AccumulatorUpdateData::try_from_slice(bytes.as_ref()).unwrap()
        };

        match accumulator_update.proof {
            pythnet_sdk::wire::v1::Proof::WormholeMerkle { vaa, updates } => {
                let vaa = {
                    let vaa: wormhole_sdk::Vaa<&serde_wormhole::RawMessage> =
                        serde_wormhole::from_slice(&vaa.as_ref()).unwrap();
                    crate::pyth::Vaa::<_, 1>::from_vaa_witness(cs, vaa)?
                };
                let guardian_set = pubkeys
                    .iter()
                    .map(|pk| uint256_pubkey(cs, pk))
                    .collect::<Result<Vec<_>, _>>()?;
                let updates = updates
                    .into_iter()
                    .map(|u| {
                        let update =
                            pyth::Update::<_, DEEPTH_MERKLE_TREE>::from_price_update_witness(cs, u);
                        update
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let valid = check_price_updates(cs, &vaa, &updates, &guardian_set)?;
                Boolean::enforce_equal(cs, &valid, &Boolean::Constant(true))?;
            }
        }
        Ok(())
    }

    fn uint256_pubkey<E: Engine, CS: ConstraintSystem<E>>(
        cs: &mut CS,
        hex_str: &str,
    ) -> Result<(UInt256<E>, UInt256<E>), SynthesisError> {
        let data = hex::decode(hex_str).map_err(new_synthesis_error)?;
        if data.len() != 64 {
            return Err(new_synthesis_error(format!(
                "hex string must be 64 characters long, got {}",
                hex_str.len()
            )));
        }
        let x = uint256_from_bytes_witness(cs, &data[0..32])?;
        let y = uint256_from_bytes_witness(cs, &data[32..])?;
        Ok((x, y))
    }
}
