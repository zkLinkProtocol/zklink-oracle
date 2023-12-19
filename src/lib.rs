use pairing::Engine;
use pyth::WormholeMessage;
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

pub fn check_price_updates<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    vaa: &WormholeMessage<E>,
    updates: &[pyth::Update<E>],
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
    use pairing::Engine;
    use sync_vm::{
        franklin_crypto::{
            bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
            plonk::circuit::boolean::Boolean,
        },
        vm::primitives::uint256::UInt256,
    };

    use crate::{
        check_price_updates, pyth,
        utils::{
            new_synthesis_error,
            testing::{create_test_constraint_system, get_accumulator_update},
            uint256_from_bytes_witness,
        },
    };

    #[test]
    fn test_integration() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let pubkeys = [ "2a953a2e8b1052eb70c1d7b556b087deed598b55608396686c1c811b9796c763078687ce10459f4f25fb7a0fbf8727bb0fb51e00820e93a123f652ee843cf08d", ];
        let (_, accumulator_update) = get_accumulator_update();
        match accumulator_update.proof {
            pythnet_sdk::wire::v1::Proof::WormholeMerkle { vaa, updates } => {
                let vaa = {
                    let vaa: wormhole_sdk::Vaa<&serde_wormhole::RawMessage> =
                        serde_wormhole::from_slice(&vaa.as_ref()).unwrap();
                    crate::pyth::WormholeMessage::<_>::alloc_from_witness(cs, vaa)?
                };
                let guardian_set = pubkeys
                    .iter()
                    .map(|pk| uint256_pubkey(cs, pk))
                    .collect::<Result<Vec<_>, _>>()?;
                let updates = updates
                    .into_iter()
                    .map(|u| {
                        let update = pyth::Update::<_>::alloc_from_witness(cs, u);
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
