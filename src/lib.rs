use pairing::Engine;
use pythnet_sdk::wire::v1::AccumulatorUpdateData;
use sync_vm::franklin_crypto::{
    bellman::{
        plonk::better_better_cs::cs::{Circuit, ConstraintSystem, Width4MainGateWithDNext},
        SynthesisError,
    },
    plonk::circuit::boolean::Boolean,
};

use crate::{
    gadgets::ethereum::Address,
    pyth::{PriceUpdate, PriceUpdates, Vaa},
    utils::new_synthesis_error,
};

pub mod gadgets;
pub mod pyth;
pub mod utils;

pub struct ZkLinkOracle<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICE: usize> {
    pub accumulator_update_data: Vec<AccumulatorUpdateData>,
    pub guardian_set: Vec<[u8; 20]>,
    pub _marker: std::marker::PhantomData<E>,
}

impl<E: Engine, const NUM_SIGNATURES_TO_VERIFY: usize, const NUM_PRICES: usize> Circuit<E>
    for ZkLinkOracle<E, NUM_SIGNATURES_TO_VERIFY, NUM_PRICES>
{
    type MainGate = Width4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
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
                    .map(|u| {
                        let update = PriceUpdate::<_>::from_price_update_witness(cs, u);
                        update
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let len = updates.len();
                updates.try_into().map_err(|_| {
                    new_synthesis_error(format!("expected {} prices, got {}", NUM_PRICES, len))
                })?
            };
            let price_updates = PriceUpdates { vaa, price_updates };
            let guardian_set = self
                .guardian_set
                .iter()
                .map(|w| Address::from_address_wtiness(cs, w))
                .collect::<Result<Vec<_>, _>>()?;
            let is_valid = price_updates.check_by_address(cs, &guardian_set)?;
            // TODO: check price commitment
            Boolean::enforce_equal(cs, &is_valid, &Boolean::Constant(true))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use pairing::bn256::Bn256;
    use pythnet_sdk::wire::v1::AccumulatorUpdateData;
    use sync_vm::franklin_crypto::bellman::{plonk::better_better_cs::cs::Circuit, SynthesisError};

    use crate::{
        utils::{new_synthesis_error, testing::create_test_constraint_system},
        ZkLinkOracle,
    };

    #[test]
    fn test_zklink_oracle() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let accumulator_update_data = {
            // base64 encoded hex from hermes API /api/latest_vaas (https://hermes.pyth.network/docs/#/rest/latest_vaas)
            let hex = "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";
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(hex)
                .unwrap();
            AccumulatorUpdateData::try_from_slice(bytes.as_ref()).unwrap()
        };
        let guardian_set = vec![
            "58CC3AE5C097b213cE3c81979e1B9f9570746AA5",
            "fF6CB952589BDE862c25Ef4392132fb9D4A42157",
            "114De8460193bdf3A2fCf81f86a09765F4762fD1",
            "107A0086b32d7A0977926A205131d8731D39cbEB",
            "8C82B2fd82FaeD2711d59AF0F2499D16e726f6b2",
            "11b39756C042441BE6D8650b69b54EbE715E2343",
            "54Ce5B4D348fb74B958e8966e2ec3dBd4958a7cd",
            "eB5F7389Fa26941519f0863349C223b73a6DDEE7",
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
        ];
        let guardian_set = guardian_set
            .into_iter()
            .map(|guardian| hex::decode(guardian).map(|bytes| bytes.try_into().unwrap()))
            .collect::<Result<Vec<[u8; 20]>, _>>()
            .map_err(new_synthesis_error)?;
        let zklink_oracle = ZkLinkOracle::<Bn256, 1, 4> {
            accumulator_update_data: vec![accumulator_update_data],
            guardian_set,
            _marker: std::marker::PhantomData,
        };
        zklink_oracle.synthesize(cs)?;
        println!("circuit contains {} gates", cs.n());
        Ok(())
    }
}
