use base64::Engine;
use pairing::bn256::Bn256;
use pythnet_sdk::wire::v1::AccumulatorUpdateData;
use sync_vm::{
    franklin_crypto::{
        bellman::{
            plonk::better_better_cs::{
                cs::{
                    ConstraintSystem, PlonkCsWidth4WithNextStepAndCustomGatesParams,
                    TrivialAssembly,
                },
                data_structures::PolyIdentifier,
                gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext,
                lookup_tables::LookupTableApplication,
            },
            SynthesisError,
        },
        plonk::circuit::{
            boolean::Boolean,
            tables::inscribe_default_range_table_for_bit_width_over_first_three_columns,
        },
    },
    vm::{tables::BitwiseLogicTable, VM_BITWISE_LOGICAL_OPS_TABLE_NAME},
};

use zklink_oracle::{
    pyth::{PriceUpdate, PriceUpdates, Vaa},
    utils::{new_synthesis_error, uint256_from_bytes_witness},
};

const NUM_SIGNATURES: usize = 1;
const NUM_PRICES: usize = 4;

fn main() -> Result<(), SynthesisError> {
    let cs = &mut get_cs()?;
    let accumulator_update = {
        // base64 encoded hex from hermes API /api/latest_vaas (https://hermes.pyth.network/docs/#/rest/latest_vaas)
        let hex = "UE5BVQEAAAADuAEAAAADDQDV3x0nSkAsXrTItgJU8dHfZ8ZMav3dde0DViqsbUrQcUvQh08IN2g77DNXmZpMLZIveekIw5pab/TsbiGniVb6AAIeMvZklctlcEnwSyUWKYETldCC1K7O6KleRH6DNypOlEOmR/RIgPPactWN/A+fqWPkqsDCgzQtmpHE4Z08pipbAQM4G/3whTu/D3tMtNZYUax/YNzJuj2EQsld5hQQy/Ce8nlFT6cl/S6QaX9V4GUAWtZOZpbACf0XZ7e/m3lzg5m/AAaCYMl4ZcOGo0lqpW2iMnFZmYqx2yaueQEGhfdVGNTuy2fNoM2kQIpjYwHQ03bz/3HbZvCI4k2HG/j511+QG4ToAQdDuLf3tNU+VJm8DSVIqVLLK2VZ2hoFg9MSjZMJJsbPKB/1iCjFTMnjnHdLcPtat6tADqpjVrwGcAsvdExqE/0GAQhZ+SuL1vpsslfVpBMntIwqyIB3PtpmF/hRGoADpW//FVArK5D2XL4W3f2iMk49C0A5+6MzLN4q30jwHkbocXg5AAovz1NKU8PlOt3wLepQpuh7IPQZInCKOHaK9q1I3FPKD2WERTDIQvJ0bs70qVCEPirf3R+HZeOhcuNGp5P+E2uQAQvzAisPSSe2twGoTpSdpM+svIzC5yA3UWwboS73o1TnfEVIIoeNfZSOUMDnEYz8oqTVozgQ58XPY6R6ARXLPF+YAAwGwBMI5F5NlXEec17y755e3erx4KUvryjg6csrN6zeeUVX1s5GOse5wW91Pd0UL1cWxkv+PJwBlg8H1Gyv1xV+AQ1c0ZnN2wfGLJXrPRmaMk55OSVir1VoozhC4jwaDyVQoQEPakryk9ZR4TrLil8ZZ9pyLfhCLuhxcxyg2eCpCPx/AQ7MGERv878qEpQBlnVW333ju/zCw31EQc3hHXG4aoEoqiLiFU5JQ1cK7R0qqnR93BBylwJoi3B1Gp2cQRueAnHaABCSLdmJDqmesy/7P+L82iJYuHUUdgGvS61Sjt9woz84K3m07xUVp8WqYK8Wp1xVXXFLTOezEnXUtOtCcImEn/CSABKZfKZex/zwQY/QNt3q1XQyBqejUP1EYCdZpLuirPyUmSQkTbPRLXaIXBYrmIE15kLB1sJ6pLpQRmjHky036tkbAGVcz/gAAAAAABrhAfrtrFhR4yubI7X5QRqMK6xKrj7U3XuBHdGnLqSqcQAAAAABlfqkAUFVV1YAAAAAAAabmTwAACcQCVu35fo3TqCGA6ZpgSPZkQFUelAEAFUA5i32yLSoX+GmfbRNwS3l2zMPesZrctxliv7fD0pBW0MAAANSgT69wAAAAABC7rn2////+AAAAABlXM/3AAAAAGVcz/cAAANW0Kdc4AAAAABbDXESCtl6Mb6MCTk7+82Mw2pMSGlJ6qsrvm4ZKUNnwWibdSG6MbzVBLAdtKDHSlbRN3la7+LfkTfBp9gq9kjLiu7ONIKg1hlOw20tqztJEpb12ZR7W4e6xeWMJ2DEZ34LuZRhj7XF2FP+zFU1HNaKUCnUvCtvmrXCPnuUYq9RSoR1/6GB6hIW0qjzRHRk+Ghfm5Nc5RJOhy1Ki56hb5SHlS3/HOai715yTU2h5fK/iX5SrGoxrGCGh3YWP2q48ddCFBhNp5UrxzH/UfAfAFUA035FE+viNf/4HkU9QA3rr5pJpd8rf6oRs4MdNdfnLLcAAAAAAAObyAAAAAAAAAGc////+AAAAABlXM/3AAAAAGVcz/cAAAAAAAOrzQAAAAAAAAH4CsOc579fDc5yB9Gtvuf+jBpLQfg8/2Bxm45T5XK4M8JvS3b8m4qL69dJImdG9pFcQOLuNCtacy/Vl7NJaM+W8azNYCwv7su8AioE1Yb1c6fnF+q/BiQxLyRtpxSqkVDrULzRHmuDFV0tmxYQl1CWeLQCHcIFlLhvK7l5kC3qPgXPBb0BoPJCP4kg2pecm5Nc5RJOhy1Ki56hb5SHlS3/HOai715yTU2h5fK/iX5SrGoxrGCGh3YWP2q48ddCFBhNp5UrxzH/UfAfAFUAA65Nsp7UrjPTI1aIlaoAM35ljjSLN1CfU3KuUfCvANUAAAAAKh9MuAAAAAAABdYf////+AAAAABlXM/3AAAAAGVcz/cAAAAAKmfKJgAAAAAAB9nMClQd/95AYaefJWi7vD12+p2/Gy7kxbooxzSK2KHCE4vp55aLAD7MtQMRghOw4IvDPfQViQQKN1uAyudjPcs2/rev778LaJ/UH43xD/Y9fC3JVSYyJV6xmI7I61cZppsd/PaGJUoFy7Edslz8h5oGI9IK/1B1ikUyBpvqB/pHxXu7go8M2tE0jzGO9MvrswlmZueizTBlA23Nt97Rxuo/7k5x0fswj+DE5eCG7cFHbdtqGWEbqXYWP2q48ddCFBhNp5UrxzH/UfAfAFUAB617SnZi0ZprxnX2tGcXLS85R/plPKl1VamyAjZAZigAAAAAFS+dvwAAAAAAB5b6////+AAAAABlXM/3AAAAAGVcz/cAAAAAFXGPJgAAAAAACHRcCscHPPaWlTWcUjKUCTkPF7jyd3DIIQ62B3qSFR5gV/o9q1GBRjTV/mdAbW+cWhbMo17bPJsrpN26K+dRE6nl5B/piCbwO5M6e4BCz+jR5azpVSYyJV6xmI7I61cZppsd/PaGJUoFy7Edslz8h5oGI9IK/1B1ikUyBpvqB/pHxXu7go8M2tE0jzGO9MvrswlmZueizTBlA23Nt97Rxuo/7k5x0fswj+DE5eCG7cFHbdtqGWEbqXYWP2q48ddCFBhNp5UrxzH/UfAf";
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(hex)
            .unwrap();
        AccumulatorUpdateData::try_from_slice(bytes.as_ref()).unwrap()
    };

    let pythnet_sdk::wire::v1::Proof::WormholeMerkle { vaa, updates } = accumulator_update.proof;
    let vaa = {
        let vaa: wormhole_sdk::Vaa<&serde_wormhole::RawMessage> =
            serde_wormhole::from_slice(&vaa.as_ref()).unwrap();
        Vaa::<_, NUM_SIGNATURES>::from_vaa_witness(cs, vaa)?
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

    // Public keys of wormhole guardian sets (https://wormhole.com/blockchains/).
    // You can use ethereum addresses from for direct verification but that needs more circuit constraints as the additional keccak256 computation
    // in circuit is expensive.
    let pubkeys = [
            "2a953a2e8b1052eb70c1d7b556b087deed598b55608396686c1c811b9796c763078687ce10459f4f25fb7a0fbf8727bb0fb51e00820e93a123f652ee843cf08d",
            "54177ff4a8329520b76efd86f8bfce5c942554db16e673267dc1133b3f5e230b2d8cbf90fe274946045d4491de288d736680edc2ee9ee5b1b15416b0a34806c4",
            "7fa3e98fcc2621337b217b61408a98facaabd25bad2b158438728ce863c14708cfcda1f3b50a16ca0211199079fb338d479a54546ec3c5f775af23a7d7f4fb24",
            "8edf3f9d997357a0e2c916ee090392c3a645ebac4f6cd8f826d3ecc0173b33bf06b7c14e8002fc9a5d01af9824a5cb3778472cd477e0ab378091448bca6f0417",
        ];
    let guardian_set = pubkeys
        .iter()
        .map(|pk| {
            let data = hex::decode(pk).map_err(new_synthesis_error)?;
            let x = uint256_from_bytes_witness(cs, &data[0..32])?;
            let y = uint256_from_bytes_witness(cs, &data[32..])?;
            Ok::<_, SynthesisError>((x, y))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let is_valid = price_updates.check(cs, &guardian_set)?;
    println!("circuit contains {} gates", cs.n());
    Boolean::enforce_equal(cs, &is_valid, &Boolean::Constant(true))?;
    cs.finalize();
    assert!(cs.is_finalized);
    Ok(())
}

pub fn get_cs() -> Result<
    TrivialAssembly<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
    >,
    SynthesisError,
> {
    let (mut cs, _, _) = sync_vm::testing::create_test_artifacts_with_optimized_gate();
    let columns3 = vec![
        PolyIdentifier::VariablesPolynomial(0),
        PolyIdentifier::VariablesPolynomial(1),
        PolyIdentifier::VariablesPolynomial(2),
    ];

    if cs.get_table(VM_BITWISE_LOGICAL_OPS_TABLE_NAME).is_err() {
        let name = VM_BITWISE_LOGICAL_OPS_TABLE_NAME;
        let bitwise_logic_table = LookupTableApplication::new(
            name,
            BitwiseLogicTable::new(&name, 8),
            columns3.clone(),
            None,
            true,
        );
        cs.add_table(bitwise_logic_table)?;
    };
    inscribe_default_range_table_for_bit_width_over_first_three_columns(&mut cs, 16)?;
    Ok(cs)
}
