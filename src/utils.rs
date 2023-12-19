use num_bigint::BigUint;
use pairing::ff::{PrimeField, ScalarEngine};
use pairing::Engine;
use std::str::FromStr;
use sync_vm::circuit_structures::byte::Byte;
use sync_vm::franklin_crypto::bellman::SynthesisError;
use sync_vm::franklin_crypto::plonk::circuit::boolean::Boolean;
use sync_vm::traits::CSAllocatable;
use sync_vm::{
    franklin_crypto::{
        bellman::plonk::better_better_cs::cs::ConstraintSystem, plonk::circuit::allocated_num::Num,
    },
    vm::primitives::uint256::UInt256,
};

pub fn new_synthesis_error<T: ToString>(msg: T) -> SynthesisError {
    let err = std::io::Error::new(std::io::ErrorKind::Other, msg.to_string());
    SynthesisError::from(err)
}

pub fn num_from_be_bytes<CS: ConstraintSystem<E>, E: Engine>(
    cs: &mut CS,
    hash: &[Byte<E>],
) -> Result<Num<E>, SynthesisError> {
    let mut bytes = [Byte::zero(); 32];
    let len = hash.len();
    assert!(len <= <<E as ScalarEngine>::Fr as PrimeField>::CAPACITY as usize);
    bytes[(32 - len)..].copy_from_slice(hash);
    let uint = UInt256::from_be_bytes_fixed(cs, &bytes)?;
    uint.to_num_unchecked(cs)
}

pub fn hex_from_bytes<E: Engine>(bytes: &[Byte<E>]) -> String {
    let bbs = bytes
        .iter()
        .map(|b| b.get_byte_value().unwrap())
        .collect::<Vec<_>>();
    hex::encode(bbs)
}

pub fn uint256_from_bytes_with_mask<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    bytes: &[Byte<E>],
    mask: &Boolean,
) -> Result<UInt256<E>, SynthesisError> {
    let mut chunks_be_arr = [Byte::empty(); 32];
    chunks_be_arr.copy_from_slice(&bytes[..]);
    let uint256 = UInt256::from_be_bytes_fixed(cs, &chunks_be_arr)?;
    let uint256 = uint256.mask(cs, mask)?;
    Ok(uint256)
}

pub fn uint256_from_bytes<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    bytes: &[Byte<E>],
) -> Result<UInt256<E>, SynthesisError> {
    let mut chunks_be_arr = [Byte::empty(); 32];
    chunks_be_arr.copy_from_slice(&bytes[..]);
    let uint256 = UInt256::from_be_bytes_fixed(cs, &chunks_be_arr)?;
    Ok(uint256)
}

// TODO: rename witness
pub fn uint256_from_bytes_witness<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    bytes: &[u8],
) -> Result<UInt256<E>, SynthesisError> {
    let uint256 = BigUint::from_bytes_be(bytes);
    UInt256::alloc_from_witness(cs, Some(uint256))
}

pub fn uint256_and_num_from_repr_witness<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    str: &str,
) -> Result<(UInt256<E>, [Num<E>; 32]), SynthesisError> {
    let biguint = BigUint::from_str(str).map_err(|e| {
        let err = std::io::Error::new(std::io::ErrorKind::Other, e);
        SynthesisError::from(err)
    })?;
    UInt256::alloc_from_biguint_and_return_u8_chunks(cs, Some(biguint))
}

pub fn uint256_from_repr_witness<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    str: &str,
) -> Result<UInt256<E>, SynthesisError> {
    Ok(uint256_and_num_from_repr_witness(cs, str)?.0)
}

pub fn uint256_constant_from_be_hex_str<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    str: &str,
) -> Result<UInt256<E>, SynthesisError> {
    let bytes = hex::decode(str)
        .unwrap()
        .into_iter()
        .map(|b| Byte::constant(b))
        .collect::<Vec<_>>();
    let bytes: [Byte<E>; 32] = bytes.try_into().unwrap();
    UInt256::from_be_bytes_fixed(cs, &bytes)
}

pub fn bytes_constant_from_hex_str<E: Engine>(
    hex_str: &str,
) -> Result<Vec<Byte<E>>, SynthesisError> {
    let bytes = hex::decode(hex_str)
        .map_err(new_synthesis_error)?
        .into_iter()
        .map(|b| Byte::<E>::constant(b))
        .collect::<Vec<_>>();
    Ok(bytes)
}

#[cfg(test)]
pub mod testing {
    use base64::Engine as _;
    use pairing::{bn256::Bn256, Engine};
    use pythnet_sdk::wire::v1::AccumulatorUpdateData;
    use sync_vm::{
        circuit_structures::byte::Byte,
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
            plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns,
        },
        vm::{tables::BitwiseLogicTable, VM_BITWISE_LOGICAL_OPS_TABLE_NAME},
    };

    pub fn bytes_assert_eq<E: Engine, T: ToString>(bytes: &[Byte<E>], expected_hex: T) {
        let bytes = bytes
            .into_iter()
            .map(|b| b.get_byte_value().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(hex::encode(&bytes), expected_hex.to_string());
    }

    pub fn create_test_constraint_system() -> Result<
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

    pub fn get_accumulator_update() -> (&'static str, AccumulatorUpdateData) {
        let hex = "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";
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(hex)
            .unwrap();
        let accumulator_update_data =
            AccumulatorUpdateData::try_from_slice(bytes.as_ref()).unwrap();
        (hex, accumulator_update_data)
    }
}
