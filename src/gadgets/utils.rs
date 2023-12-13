use pairing::{
    ff::{PrimeField, ScalarEngine},
    Engine,
};
use sync_vm::{
    circuit_structures::byte::Byte,
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::allocated_num::Num,
    },
    vm::primitives::uint256::UInt256,
};

pub fn bytes_be_to_num<CS: ConstraintSystem<E>, E: Engine>(
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

fn bytes_to_hex<E: Engine>(bytes: &[Byte<E>]) -> String {
    let bbs = bytes
        .iter()
        .map(|b| b.get_byte_value().unwrap())
        .collect::<Vec<_>>();
    hex::encode(bbs)
}
