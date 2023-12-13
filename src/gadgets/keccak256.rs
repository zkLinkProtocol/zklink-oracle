use pairing::Engine;
use sync_vm::{
    circuit_structures::byte::Byte,
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::{
            hashes_with_tables::keccak::gadgets::Keccak256Gadget,
            tables::RANGE_CHECK_SINGLE_APPLICATION_TABLE_NAME,
        },
    },
    scheduler::block_header::keccak_output_into_bytes,
};

// cost: 26723 gates for each block
pub fn digest<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    bytes: &[Byte<E>],
) -> Result<[Byte<E>; 32], SynthesisError> {
    let keccak_gadget = Keccak256Gadget::new(
        cs,
        None,
        None,
        None,
        None,
        true,
        RANGE_CHECK_SINGLE_APPLICATION_TABLE_NAME,
    )?;
    let result = keccak_gadget.digest_from_bytes(cs, &bytes)?;
    let digest = keccak_output_into_bytes(cs, result)?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use sync_vm::{circuit_structures::byte::Byte, franklin_crypto::bellman::SynthesisError};

    use crate::gadgets::testing::create_test_constraint_system;

    #[test]
    fn test_keccak256() -> Result<(), SynthesisError> {
        let mut cs = create_test_constraint_system()?;
        let cs = &mut cs;
        let n = cs.n();
        let input = b"hello world";
        let input_bytes = input
            .iter()
            .map(|b| Byte::from_u8_witness(cs, Some(*b)).unwrap())
            .collect::<Vec<_>>();
        let digest = super::digest(cs, &input_bytes)?;
        let digest = Byte::get_byte_value_multiple(&digest).unwrap();
        assert_eq!(
            hex::encode(digest),
            "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
        );
        let n = cs.n() - n;
        println!("Roughly {} gates", n);
        assert!(cs.is_satisfied());
        Ok(())
    }
}
