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
}
