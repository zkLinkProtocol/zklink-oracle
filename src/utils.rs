use num_bigint::BigUint;
use pairing::ff::{PrimeField, ScalarEngine};
use pairing::Engine;
use std::str::FromStr;
use sync_vm::circuit_structures::byte::Byte;
use sync_vm::franklin_crypto::bellman::SynthesisError;
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

pub fn uint256_and_u8_chunks_from_repr<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    str: &str,
) -> Result<(UInt256<E>, [Num<E>; 32]), SynthesisError> {
    let biguint = BigUint::from_str(str).map_err(|e| {
        let err = std::io::Error::new(std::io::ErrorKind::Other, e);
        SynthesisError::from(err)
    })?;
    UInt256::alloc_from_biguint_and_return_u8_chunks(cs, Some(biguint))
}

pub fn uint256_from_repr<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    str: &str,
) -> Result<UInt256<E>, SynthesisError> {
    Ok(uint256_and_u8_chunks_from_repr(cs, str)?.0)
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
    use pairing::{bn256::Bn256, Engine};
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
}
