use std::usize;

use pairing::Engine;
use sync_vm::{
    circuit_structures::byte::Byte,
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::{allocated_num::Num, boolean::Boolean},
    },
    glue::prepacked_long_comparison,
};

use super::utils::bytes_be_to_num;

const BYTE_WIDTH: usize = 20;
const BIT_WIDTH: usize = BYTE_WIDTH * 8;
pub type Hash<E> = [Byte<E>; BYTE_WIDTH];

// cost: 26723 gates for each block
pub fn digest<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    bytes: &[Byte<E>],
) -> Result<Hash<E>, SynthesisError> {
    let digest256 = super::keccak256::digest(cs, bytes)?;
    let mut digest160 = [Byte::<E>::zero(); BYTE_WIDTH];
    digest160[..].copy_from_slice(&digest256[..BYTE_WIDTH]);
    Ok(digest160)
}

// Circuit version of Pyth Merkle Merkle
// See: https://github.com/pyth-network/pyth-crosschain/blob/245cc231fd0acd5d91757ab29f474237c2a606aa/pythnet/pythnet_sdk/src/accumulators/merkle.rs#L72-L78
pub struct MerkleTree<E: Engine> {
    root: Hash<E>,
    proof: Vec<Hash<E>>,
    item: Vec<Byte<E>>,
}

impl<E: Engine> MerkleTree<E> {
    // https://github.com/pyth-network/pyth-crosschain/blob/245cc231fd0acd5d91757ab29f474237c2a606aa/pythnet/pythnet_sdk/src/accumulators/merkle.rs#L196-L198
    pub fn hash_leaf<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        item: &[Byte<E>],
    ) -> Result<Hash<E>, SynthesisError> {
        let mut bytes = vec![Byte::zero()];
        bytes.extend_from_slice(item);
        digest(cs, &bytes)
    }

    pub fn hash_node<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        l: Hash<E>,
        r: Hash<E>,
    ) -> Result<Hash<E>, SynthesisError> {
        let ln = bytes_be_to_num(cs, &l)?;
        let rn = bytes_be_to_num(cs, &r)?;
        let (_, l_is_greater) = prepacked_long_comparison(cs, &[ln], &[rn], &[BIT_WIDTH])?;
        let (l, r): (Hash<_>, Hash<_>) = {
            let zipped = (0..BYTE_WIDTH)
                .into_iter()
                .map(|i| {
                    let li = l[i].inner;
                    let ri = r[i].inner;
                    // reverse if l_is_greater is true
                    let (li, ri) = Num::conditionally_reverse(cs, &li, &ri, &l_is_greater)?;
                    Ok((
                        Byte::from_num_unconstrained(cs, li),
                        Byte::from_num_unconstrained(cs, ri),
                    ))
                    // (1u8, 1u8)
                })
                .collect::<Result<Vec<_>, SynthesisError>>()?;
            let (l, r): (Vec<_>, Vec<_>) = zipped.into_iter().unzip();
            (l.try_into().unwrap(), r.try_into().unwrap())
        };
        // https://github.com/pyth-network/pyth-crosschain/blob/245cc231fd0acd5d91757ab29f474237c2a606aa/pythnet/pythnet_sdk/src/accumulators/merkle.rs#L201-L207
        let mut bytes = [Byte::zero(); 1 + BYTE_WIDTH * 2];
        bytes[0] = Byte::<E>::constant(1);
        bytes[1..BYTE_WIDTH + 1].copy_from_slice(&l[..]);
        bytes[BYTE_WIDTH + 1..].copy_from_slice(&r[..]);
        digest(cs, &bytes)
    }

    // https://github.com/pyth-network/pyth-crosschain/blob/245cc231fd0acd5d91757ab29f474237c2a606aa/pythnet/pythnet_sdk/src/accumulators/merkle.rs#L88-L94
    pub fn check<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<Boolean, SynthesisError> {
        let mut current = Self::hash_leaf(cs, &self.item)?;
        for hash in &self.proof {
            let (l, r) = (current, *hash);
            current = Self::hash_node(cs, l, r)?;
        }
        let current = bytes_be_to_num(cs, &current)?;
        let root = bytes_be_to_num(cs, &self.root)?;
        Num::equals(cs, &current, &root)
    }
}

#[cfg(test)]
mod tests {
    use super::Hash;
    use pairing::Engine;
    use sync_vm::{
        circuit_structures::byte::Byte,
        franklin_crypto::{
            bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
            plonk::circuit::boolean::Boolean,
        },
    };

    use super::super::{keccak160::MerkleTree, testing::create_test_constraint_system};

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

    fn hex_to_hash<E: Engine, CS: ConstraintSystem<E>>(cs: &mut CS, hex: &str) -> Hash<E> {
        let mut hash = [0u8; 20];
        hex::decode_to_slice(hex, &mut hash).unwrap();
        hash.map(|b| Byte::from_u8_witness(cs, Some(b)).unwrap())
    }
    fn hex_to_bytes<E: Engine, CS: ConstraintSystem<E>>(cs: &mut CS, hex: &str) -> Vec<Byte<E>> {
        let bytes = hex::decode(hex).unwrap();
        bytes
            .iter()
            .map(|b| Byte::from_u8_witness(cs, Some(*b)).unwrap())
            .collect::<Vec<_>>()
    }

    #[test]
    fn test_merkle_tree() -> Result<(), SynthesisError> {
        let mut cs = create_test_constraint_system()?;
        let cs = &mut cs;
        let merkle_tree = MerkleTree {
            root: hex_to_hash(cs, "095bb7e5fa374ea08603a6698123d99101547a50"),
            proof: [
                "c7073cf69695359c52329409390f17b8f27770c8",
                "210eb6077a92151e6057fa3dab51814634d5fe67",
                "406d6f9c5a16cca35edb3c9b2ba4ddba2be75113",
                "a9e5e41fe98826f03b933a7b8042cfe8d1e5ace9",
                "552632255eb1988ec8eb5719a69b1dfcf686254a",
                "05cbb11db25cfc879a0623d20aff50758a453206",
                "9bea07fa47c57bbb828f0cdad1348f318ef4cbeb",
                "b3096666e7a2cd3065036dcdb7ded1c6ea3fee4e",
                "71d1fb308fe0c4e5e086edc1476ddb6a19611ba9",
                "76163f6ab8f1d74214184da7952bc731ff51f01f",
            ].iter().map(|h| hex_to_hash(cs, h)).collect::<Vec<_>>(),
            item: hex_to_bytes(cs, "0007ad7b4a7662d19a6bc675f6b467172d2f3947fa653ca97555a9b2023640662800000000152f9dbf00000000000796fafffffff800000000655ccff700000000655ccff70000000015718f26000000000008745c"),
        };
        let n = cs.n();
        let valid = merkle_tree.check(cs)?;
        Boolean::enforce_equal(cs, &valid, &Boolean::constant(true))?;
        let n = cs.n() - n;
        println!("Roughly {} gates", n);
        assert!(cs.is_satisfied());
        Ok(())
    }
}
