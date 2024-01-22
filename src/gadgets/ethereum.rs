use core::fmt;

use num::traits::{FromBytes, ToBytes};
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

/// Circuit representation of Ethereum address.
pub struct Address<E: Engine>(UInt256<E>);

impl<E: Engine> fmt::Display for Address<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr = self.0.get_value().unwrap();
        let bytes = addr.to_be_bytes();
        let hex = hex::encode(bytes);
        write!(f, "{}", hex)
    }
}

impl<E: Engine> Address<E> {
    pub fn new(uint: UInt256<E>) -> Self {
        Self(uint)
    }

    pub fn inner(&self) -> UInt256<E> {
        self.0
    }

    /// Returns 0 address if condition is false, else self.
    pub fn mask<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        condition: &Boolean,
    ) -> Result<Self, SynthesisError> {
        Ok(Self(self.0.mask(cs, condition)?))
    }

    /// Create address from bytes.
    pub fn from_bytes<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        bytes: &[Byte<E>; 20],
    ) -> Result<Self, SynthesisError> {
        let mut chunks_be_arr = [Byte::zero(); 32];
        chunks_be_arr[12..].copy_from_slice(&bytes[..]);
        let uint256 = utils::uint256_from_bytes(cs, &chunks_be_arr)?;
        Ok(Self(uint256))
    }

    /// Create address from public key x and y coordinates.
    pub fn from_pubkey<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        x: &[Byte<E>; 32],
        y: &[Byte<E>; 32],
    ) -> Result<Self, SynthesisError> {
        let mut chunks_be_arr = [Byte::zero(); 64];
        chunks_be_arr[..32].copy_from_slice(&x[..]);
        chunks_be_arr[32..].copy_from_slice(&y[..]);
        let hash1 = super::keccak256::digest(cs, &chunks_be_arr)?;
        let mut hash = [Byte::<E>::zero(); 20];
        hash[..].copy_from_slice(&hash1[12..]);
        Self::from_bytes(cs, &hash)
    }

    pub fn from_address_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        witness: &[u8; 20],
    ) -> Result<Self, SynthesisError> {
        let mut chunks_be_arr = [0u8; 32];
        chunks_be_arr[12..].copy_from_slice(&witness[..]);
        let uint256 = BigUint::from_be_bytes(&chunks_be_arr);
        let uint256 = UInt256::alloc_from_biguint(cs, Some(uint256))?;
        Ok(Self(uint256))
    }

    /// Create address from public key witness in compressed / uncompressed format.
    pub fn from_pubkey_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        witness: &[u8],
    ) -> Result<Self, SynthesisError> {
        let pubkey = secp256k1::PublicKey::from_slice(witness).map_err(new_synthesis_error)?;
        let bytes = pubkey.serialize_uncompressed();
        use sha3::Digest as _;
        let address: [u8; 32] = sha3::Keccak256::new_with_prefix(&bytes[1..])
            .finalize()
            .into();
        let address: [u8; 20] = address[address.len() - 20..].try_into().unwrap();
        Self::from_address_witness(cs, &address)
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
    use sync_vm::{
        circuit_structures::byte::Byte,
        franklin_crypto::{bellman::SynthesisError, plonk::circuit::boolean::Boolean},
    };

    use crate::{
        gadgets::ethereum::Address,
        utils::{new_synthesis_error, testing::create_test_constraint_system},
    };

    #[test]
    fn test_address_from_witness() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let addr1 = Address::from_pubkey_witness(cs,
            &hex::decode("042a953a2e8b1052eb70c1d7b556b087deed598b55608396686c1c811b9796c763078687ce10459f4f25fb7a0fbf8727bb0fb51e00820e93a123f652ee843cf08d").unwrap())?;
        let addr2 = Address::from_address_witness(
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

    #[test]
    fn test_address_from_pubkey() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let pubkey = "2a953a2e8b1052eb70c1d7b556b087deed598b55608396686c1c811b9796c763078687ce10459f4f25fb7a0fbf8727bb0fb51e00820e93a123f652ee843cf08d";
        let data = hex::decode(pubkey).map_err(new_synthesis_error)?;
        let x = &data[0..32]
            .iter()
            .map(|b| Byte::from_u8_witness(cs, Some(*b)))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();
        let y = &data[32..]
            .iter()
            .map(|b| Byte::from_u8_witness(cs, Some(*b)))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();
        let addr1 = Address::from_pubkey(cs, &x, &y)?;
        let addr2 = Address::from_address_witness(
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
