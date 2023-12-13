use pairing::Engine;
use sync_vm::{
    circuit_structures::byte::Byte,
    franklin_crypto::bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
};

type Hash<E> = [Byte<E>; 20];

// cost: 26723 gates for each block
pub fn digest<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    bytes: &[Byte<E>],
) -> Result<Hash<E>, SynthesisError> {
    let digest256 = super::keccak256::digest(cs, bytes)?;
    let mut digest160 = [Byte::<E>::zero(); 20];
    digest160[..].copy_from_slice(&digest256[..20]);
    Ok(digest160)
}

#[cfg(test)]
mod tests {
    use sync_vm::{circuit_structures::byte::Byte, franklin_crypto::bellman::SynthesisError};

    use crate::gadgets::testing::create_test_constraint_system;

    #[test]
    fn test_keccak160() -> Result<(), SynthesisError> {
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
            "47173285a8d7341e5e972fc677286384f802f8ef"
        );
        let n = cs.n() - n;
        println!("Roughly {} gates", n);
        assert!(cs.is_satisfied());
        Ok(())
    }
}
