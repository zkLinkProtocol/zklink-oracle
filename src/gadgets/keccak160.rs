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

use crate::utils::{new_synthesis_error, num_from_be_bytes};

pub const WIDTH_HASH_BYTES: usize = 20;
pub type Hash<E> = [Byte<E>; WIDTH_HASH_BYTES];

fn hash_from_slice<E: Engine>(bytes: &[Byte<E>]) -> Result<Hash<E>, SynthesisError> {
    bytes.try_into().map_err(|_| {
        new_synthesis_error(format!(
            "invalid bytes length {}, expect {}",
            bytes.len(),
            WIDTH_HASH_BYTES
        ))
    })
}

// cost: 26723 gates for each block
pub fn digest<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    bytes: &[Byte<E>],
) -> Result<Hash<E>, SynthesisError> {
    let digest256 = super::keccak256::digest(cs, bytes)?;
    let mut digest160 = [Byte::<E>::zero(); WIDTH_HASH_BYTES];
    digest160[..].copy_from_slice(&digest256[..WIDTH_HASH_BYTES]);
    Ok(digest160)
}

/// Circuit implementation of pyth [`MerkleRoot`](https://github.com/pyth-network/pyth-crosschain/blob/245cc231fd0acd5d91757ab29f474237c2a606aa/pythnet/pythnet_sdk/src/accumulators/merkle.rs#L53-L66).
#[derive(Debug, Clone)]
pub struct MerkleRoot<E: Engine>(Hash<E>);
/// Circuit implementation of pyth
/// [`MerklePath`](https://github.com/pyth-network/pyth-crosschain/blob/245cc231fd0acd5d91757ab29f474237c2a606aa/pythnet/pythnet_sdk/src/accumulators/merkle.rs#L39-L51)
#[derive(Debug, Clone)]
pub struct MerklePath<E: Engine, const N: usize>(pub [Hash<E>; N]);

impl<E: Engine, const N: usize> MerklePath<E, N> {
    pub fn new(proof: [Hash<E>; N]) -> Self {
        Self(proof)
    }

    pub fn new_from_slice(proof: &[Hash<E>]) -> Result<Self, SynthesisError> {
        let proof = proof.try_into().map_err(|_| {
            new_synthesis_error(format!(
                "invalid proof length {}, expect {}",
                proof.len(),
                N
            ))
        })?;
        Ok(Self(proof))
    }

    pub fn len(&self) -> usize {
        N
    }
}

impl<E: Engine> MerkleRoot<E> {
    pub fn new(hash: Hash<E>) -> Self {
        Self(hash)
    }

    pub fn inner(&self) -> Hash<E> {
        self.0.clone()
    }

    /// Compute hash of a leaf node.
    pub fn hash_leaf<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        item: &[Byte<E>],
    ) -> Result<Hash<E>, SynthesisError> {
        let mut bytes = vec![Byte::zero()];
        bytes.extend_from_slice(item);
        digest(cs, &bytes)
    }

    /// Compute hash of a node.
    pub fn hash_node<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        l: Hash<E>,
        r: Hash<E>,
    ) -> Result<Hash<E>, SynthesisError> {
        let ln = num_from_be_bytes(cs, &l)?;
        let rn = num_from_be_bytes(cs, &r)?;
        let (_, l_is_greater) =
            prepacked_long_comparison(cs, &[ln], &[rn], &[WIDTH_HASH_BYTES * 8])?;
        let (l, r): (Hash<_>, Hash<_>) = {
            let zipped = (0..WIDTH_HASH_BYTES)
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

            (hash_from_slice(&l)?, hash_from_slice(&r)?)
        };
        // https://github.com/pyth-network/pyth-crosschain/blob/245cc231fd0acd5d91757ab29f474237c2a606aa/pythnet/pythnet_sdk/src/accumulators/merkle.rs#L201-L207
        let mut bytes = [Byte::zero(); 1 + WIDTH_HASH_BYTES * 2];
        bytes[0] = Byte::<E>::constant(1);
        bytes[1..WIDTH_HASH_BYTES + 1].copy_from_slice(&l[..]);
        bytes[WIDTH_HASH_BYTES + 1..].copy_from_slice(&r[..]);
        digest(cs, &bytes)
    }

    /// Check if the given item is in the merkle tree.
    pub fn check<CS: ConstraintSystem<E>, const N: usize>(
        &self,
        cs: &mut CS,
        path: &MerklePath<E, N>,
        item: &[Byte<E>],
    ) -> Result<Boolean, SynthesisError> {
        let mut current = Self::hash_leaf(cs, item)?;
        for hash in &path.0 {
            let (l, r) = (current, *hash);
            current = Self::hash_node(cs, l, r)?;
        }
        let current = num_from_be_bytes(cs, &current)?;
        let root = num_from_be_bytes(cs, &self.0)?;
        Num::equals(cs, &current, &root)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        gadgets::keccak160::{MerklePath, MerkleRoot},
        utils::testing::create_test_constraint_system,
    };

    use super::Hash;
    use pairing::Engine;
    use sync_vm::{
        circuit_structures::byte::Byte,
        franklin_crypto::{
            bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
            plonk::circuit::boolean::Boolean,
        },
    };

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
        {
            let expected_digest = hex::decode("47173285a8d7341e5e972fc677286384f802f8ef")
                .unwrap()
                .into_iter()
                .map(|b| Byte::constant(b))
                .collect::<Vec<_>>();
            for i in 0..digest.len() {
                digest[i]
                    .inner
                    .enforce_equal(cs, &expected_digest[i].inner)?;
            }
        }
        let n = cs.n() - n;
        println!("Roughly {} gates", n);
        assert!(cs.is_satisfied());
        Ok(())
    }

    fn hex_to_hash<E: Engine, CS: ConstraintSystem<E>>(cs: &mut CS, hex: &str) -> Hash<E> {
        hex_to_bytes(cs, hex).try_into().unwrap()
    }

    fn hex_to_bytes<E: Engine, CS: ConstraintSystem<E>>(cs: &mut CS, hex: &str) -> Vec<Byte<E>> {
        let bytes = hex::decode(hex).unwrap();
        bytes
            .iter()
            .map(|b| Byte::from_u8_witness(cs, Some(*b)).unwrap())
            .collect::<Vec<_>>()
    }

    #[test]
    fn test_merkle_check() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let merkle_root =
            MerkleRoot::new(hex_to_hash(cs, "095bb7e5fa374ea08603a6698123d99101547a50"));
        let merkle_path = {
            let nodes = [
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
            ]
            .map(|h| hex_to_hash(cs, h));
            MerklePath::new(nodes)
        };
        let item = hex_to_bytes(cs, "0007ad7b4a7662d19a6bc675f6b467172d2f3947fa653ca97555a9b2023640662800000000152f9dbf00000000000796fafffffff800000000655ccff700000000655ccff70000000015718f26000000000008745c");
        let n = cs.n();
        let valid = merkle_root.check(cs, &merkle_path, &item)?;
        Boolean::enforce_equal(cs, &valid, &Boolean::constant(true))?;
        let n = cs.n() - n;
        println!("Roughly {} gates", n);
        assert!(cs.is_satisfied());
        Ok(())
    }
}
