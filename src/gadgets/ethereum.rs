use num::traits::FromBytes;
use num_bigint::BigUint;
use pairing::Engine;
use sync_vm::{
    circuit_structures::byte::Byte,
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::boolean::Boolean,
    },
    vm::primitives::uint256::UInt256,
};

use crate::utils::{self, new_synthesis_error};

pub struct Address<E: Engine>(UInt256<E>);

impl<E: Engine> Address<E> {
    pub fn new(uint: UInt256<E>) -> Self {
        Self(uint)
    }

    pub fn inner(&self) -> UInt256<E> {
        self.0
    }

    pub fn from_bytes<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        bytes: &[Byte<E>; 20],
    ) -> Result<Self, SynthesisError> {
        let mut chunks_be_arr = [Byte::zero(); 32];
        chunks_be_arr[12..].copy_from_slice(&bytes[..]);
        let uint256 = utils::uint256_from_bytes(cs, &chunks_be_arr)?;
        Ok(Self(uint256))
    }

    pub fn from_pubkey_x_y<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        x: &[Byte<E>; 32],
        y: &[Byte<E>; 32],
    ) -> Result<Self, SynthesisError> {
        let mut chunks_be_arr = [Byte::zero(); 64];
        chunks_be_arr[..32].copy_from_slice(&x[..]);
        chunks_be_arr[32..].copy_from_slice(&y[..]);
        let hash1 = super::keccak256::digest(cs, &chunks_be_arr)?;
        let hash2 = super::keccak160::digest(cs, &hash1)?;
        Self::from_bytes(cs, &hash2)
    }

    pub fn from_address_wtiness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        witness: &[u8; 20],
    ) -> Result<Self, SynthesisError> {
        let mut chunks_be_arr = [0u8; 32];
        chunks_be_arr[12..].copy_from_slice(&witness[..]);
        let uint256 = BigUint::from_be_bytes(&chunks_be_arr);
        let uint256 = UInt256::alloc_from_biguint(cs, Some(uint256))?;
        Ok(Self(uint256))
    }

    // Convert from compressed / uncompressed public key
    pub fn from_pubkey_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        witness: &[u8],
    ) -> Result<Self, SynthesisError> {
        let pubkey = secp256k1::PublicKey::from_slice(witness).map_err(new_synthesis_error)?;
        let bytes = pubkey.serialize_uncompressed();
        println!("hex bytes {:?}", hex::encode(&bytes));
        use sha3::Digest as _;
        let address: [u8; 32] = sha3::Keccak256::new_with_prefix(&bytes[1..])
            .finalize()
            .into();
        let address: [u8; 20] = address[address.len() - 20..].try_into().unwrap();
        Self::from_address_wtiness(cs, &address)
    }

    pub fn equals<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        other: &Self,
    ) -> Result<Boolean, SynthesisError> {
        UInt256::equals(cs, &self.inner(), &other.inner())
    }
}

#[cfg(test)]
mod tests {
    use sync_vm::franklin_crypto::{bellman::SynthesisError, plonk::circuit::boolean::Boolean};

    use crate::{gadgets::ethereum::Address, utils::testing::create_test_constraint_system};

    #[test]
    fn test_address_from_witness() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let addr1 = Address::from_pubkey_witness(cs,
            &hex::decode("042a953a2e8b1052eb70c1d7b556b087deed598b55608396686c1c811b9796c763078687ce10459f4f25fb7a0fbf8727bb0fb51e00820e93a123f652ee843cf08d").unwrap())?;
        let addr2 = Address::from_address_wtiness(
            cs,
            &hex::decode("58cc3ae5c097b213ce3c81979e1b9f9570746aa5")
                .unwrap()
                .try_into()
                .unwrap(),
        )?;
        let is_equal = addr1.equals(cs, &addr2)?;
        Boolean::enforce_equal(cs, &is_equal, &Boolean::constant(true))?;
        Ok(())
    }
}
