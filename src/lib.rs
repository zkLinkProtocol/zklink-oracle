#[allow(dead_code)]
pub mod pyth;
pub mod gadgets;
pub mod params;
pub mod utils;

fn check_price_updates<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    vaa: &WormholeMessage<E>,
    updates: &[pyth::Update<E>],
    guardian_set: &[(UInt256<E>, UInt256<E>)],
) -> Result<Boolean, SynthesisError> {
    // Verify wormhole signature
    let recovered = vaa.ecrecover(cs)?;
    let mut ecrecover_successful = vec![];
    let mut pubkeys_matched = vec![];
    for (s, (x, y)) in recovered {
        ecrecover_successful.push(s);
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
    let mut valid_updates = vec![];
    let root = vaa.merkle_root();
    let mut i = 0;
    for update in updates {
        println!("check update: {}", i);
        i = i + 1;
        let check = update.check(cs, &root)?;
        valid_updates.push(check);
        println!("Done check update: {}", i);
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
    use sync_vm::franklin_crypto::{bellman::SynthesisError, plonk::circuit::boolean::Boolean};

    use crate::{
        check_price_updates, pyth,
        utils::testing::{create_test_constraint_system, get_accumulator_update},
    };

    #[test]
    fn test_integration() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let (_, accumulator_update) = get_accumulator_update();
        match accumulator_update.proof {
            pythnet_sdk::wire::v1::Proof::WormholeMerkle { vaa, updates } => {
                let vaa = {
                    let vaa: wormhole_sdk::Vaa<&serde_wormhole::RawMessage> =
                        serde_wormhole::from_slice(&vaa.as_ref()).unwrap();
                    crate::pyth::WormholeMessage::<_>::alloc_from_witness(cs, vaa)?
                };
                let updates = updates
                    .into_iter()
                    .map(|u| {
                        let update = pyth::Update::<_>::alloc_from_witness(cs, u);
                        update
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let valid = check_price_updates(cs, &vaa, &updates, &[])?;
                Boolean::enforce_equal(cs, &valid, &Boolean::Constant(true))?;
            }
        }
        Ok(())
    }
}
