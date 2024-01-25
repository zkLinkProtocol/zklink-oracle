use advanced_circuit_component::franklin_crypto::bellman::pairing::Engine;
use advanced_circuit_component::{
    circuit_structures::byte::{Byte, IntoBytes},
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::boolean::Boolean,
    },
    traits::CSAllocatable,
    vm::primitives::uint256::UInt256,
};

use crate::gadgets::{ecdsa::Signature, ethereum::Address};
use std::convert::TryInto;

use super::witness::{DataPackage, DataPoint};

#[derive(Clone, Debug, Copy)]
pub struct AllocatedDataPoint<E: Engine> {
    pub data_feed_id: [Byte<E>; 32],
    pub value: [Byte<E>; super::DEFAULT_NUM_VALUE_BS],
}

impl<E: Engine> AllocatedDataPoint<E> {
    pub fn from_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        witness: DataPoint,
    ) -> Result<Self, SynthesisError> {
        let data_feed_id = {
            let bytes = witness.serialize_feed_id().try_into().unwrap();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let value = {
            let bytes = witness.serialize_value().try_into().unwrap();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };

        Ok(Self {
            data_feed_id,
            value,
        })
    }

    pub fn serialize(&self) -> Result<Vec<Byte<E>>, SynthesisError> {
        let mut bytes = vec![];
        bytes.extend(self.data_feed_id);
        bytes.extend(self.value);
        Ok(bytes)
    }
}

pub struct AllocatedSignedPrice<E: Engine, const NUM_SIGNATURES: usize> {
    pub signed_data_packages: [AllocatedSignedDataPackage<E>; NUM_SIGNATURES],
}

impl<E: Engine, const NUM_SIGNATURES: usize> AllocatedSignedPrice<E, NUM_SIGNATURES> {
    pub fn from_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        witness: [(DataPackage, [u8; 65]); NUM_SIGNATURES],
    ) -> Result<Self, SynthesisError> {
        let mut signed_data_packages = vec![];
        for (data_package, signature) in witness.into_iter() {
            let signed_package_data =
                AllocatedSignedDataPackage::from_witness(cs, data_package, signature);
            signed_data_packages.push(signed_package_data?);
        }

        Ok(Self {
            signed_data_packages: signed_data_packages.try_into().unwrap(),
        })
    }

    pub fn check_by_addresses<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        guardians: &[Address<E>],
    ) -> Result<Boolean, SynthesisError> {
        let mut is_valid = Boolean::constant(true);

        for i in 0..NUM_SIGNATURES {
            let current_is_valid =
                self.signed_data_packages[i].check_by_address(cs, &guardians[i])?;
            is_valid = Boolean::and(cs, &is_valid, &current_is_valid)?;
        }
        Ok(is_valid)
    }

    pub fn timestamp(&self) -> [Byte<E>; super::TIMESTAMP_BS] {
        self.signed_data_packages[0].data_package.timestamp
    }

    pub fn price(&self) -> [Byte<E>; super::DEFAULT_NUM_VALUE_BS] {
        self.signed_data_packages[0].data_package.data_points[0].value
    }

    pub fn feed_id(&self) -> [Byte<E>; 32] {
        self.signed_data_packages[0].data_package.data_points[0].data_feed_id
    }
}

#[derive(Clone, Debug)]
pub struct AllocatedSignedDataPackage<E: Engine> {
    pub data_package: AllocatedDataPackage<E>,
    pub signature: Signature<E>,
}

impl<E: Engine> AllocatedSignedDataPackage<E> {
    pub fn from_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        data_package: DataPackage,
        signature: [u8; 65],
    ) -> Result<Self, SynthesisError> {
        let data_package = AllocatedDataPackage::from_witness(cs, data_package)?;
        let mut signature = signature;
        if signature[64] >= 27 {
            signature[64] -= 27;
        }
        let signature = Signature::from_bytes_witness(cs, &signature)?;
        Ok(Self {
            data_package,
            signature,
        })
    }

    pub fn ecrecover<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
    ) -> Result<crate::gadgets::ecdsa::EcRecoverRes<E>, SynthesisError> {
        let msg_hash = {
            let bytes = self.data_package.serialize()?;
            use crate::gadgets::keccak256::digest;
            let hash = digest(cs, &bytes)?;
            UInt256::from_be_bytes_fixed(cs, &hash)?
        };

        let pubkey = self.signature.ecrecover(cs, &msg_hash)?;
        Ok(pubkey)
    }

    pub fn check_by_address<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
        guardian: &Address<E>,
    ) -> Result<Boolean, SynthesisError> {
        let (successful, (x, y)) = self.ecrecover(cs)?;

        let is_matched = {
            let (x, y) = (
                x.into_be_bytes(cs)?.try_into().unwrap(),
                y.into_be_bytes(cs)?.try_into().unwrap(),
            );
            let address = Address::from_pubkey(cs, &x, &y)?;
            guardian.equals(cs, &address)?
        };

        let is_ok = Boolean::and(cs, &is_matched, &successful)?;
        Ok(is_ok)
    }
}

#[derive(Clone, Debug)]
pub struct AllocatedDataPackage<E: Engine> {
    pub data_points: Vec<AllocatedDataPoint<E>>,
    pub timestamp: [Byte<E>; super::TIMESTAMP_BS],
    pub data_points_count: [Byte<E>; super::DATA_POINTS_COUNT_BS],
    pub default_data_point_value_byte_size: [Byte<E>; super::DATA_POINT_VALUE_BYTE_SIZE_BS],
}

impl<E: Engine> AllocatedDataPackage<E> {
    pub fn from_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        witness: DataPackage,
    ) -> Result<Self, SynthesisError> {
        let timestamp = {
            let bytes = witness.serialize_timestamp().try_into().unwrap();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let data_points_count = {
            let bytes = witness.serialize_data_points_count().try_into().unwrap();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };
        let default_data_point_value_byte_size = {
            let bytes = witness
                .serialize_default_data_point_byte_size()
                .try_into()
                .unwrap();
            CSAllocatable::alloc_from_witness(cs, Some(bytes))?
        };

        let data_points = witness.sorted_data_points();
        let data_points = data_points
            .into_iter()
            .map(|data_point| AllocatedDataPoint::from_witness(cs, data_point))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            data_points,
            timestamp,
            data_points_count,
            default_data_point_value_byte_size,
        })
    }

    pub fn serialize(&self) -> Result<Vec<Byte<E>>, SynthesisError> {
        let mut bytes = vec![];
        for data_point in self.data_points.iter() {
            bytes.extend(data_point.serialize()?);
        }
        bytes.extend(self.timestamp);
        bytes.extend(self.default_data_point_value_byte_size);
        bytes.extend(self.data_points_count);
        Ok(bytes)
    }

    pub fn keccak256_hash<CS: ConstraintSystem<E>>(
        &self,
        cs: &mut CS,
    ) -> Result<[Byte<E>; 32], SynthesisError> {
        let bytes = self.serialize()?;
        use crate::gadgets::keccak256::digest;
        digest(cs, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use advanced_circuit_component::franklin_crypto::bellman::SynthesisError;

    use crate::{
        gadgets::ethereum::Address,
        redstone::witness::{DataPackage, DataPoint},
        utils::testing::{bytes_assert_eq, create_test_constraint_system},
    };

    use super::AllocatedDataPackage;

    #[test]
    fn test_serialize_and_hash() -> Result<(), SynthesisError> {
        let data_package = DataPackage::new(
            vec![
                DataPoint::new("BTC", "20000"),
                DataPoint::new("ETH", "1000"),
            ],
            1654353400000u64,
        );
        let cs = &mut create_test_constraint_system()?;
        let allocated_data_package = AllocatedDataPackage::from_witness(cs, data_package)
            .expect("should create circuit data package");
        let hash = allocated_data_package.keccak256_hash(cs)?;
        bytes_assert_eq(
            &hash,
            "e27cdb508629d3bbbb93739f48f282e89374eb5ea105cf519abd68a249cc2070",
        );
        println!("DONE");
        Ok(())
    }

    #[test]
    fn test_check_by_address() -> Result<(), SynthesisError> {
        let cs = &mut create_test_constraint_system()?;
        let address = Address::from_address_witness(
            cs,
            &hex::decode("109B4a318A4F5ddcbCA6349B45f881B4137deaFB")
                .unwrap()
                .try_into()
                .unwrap(),
        )?;
        let signature  = hex::decode("9ad1f96c083cf31f757b33b0ef6b2c4279589bf0489c1c3a7beb0005d2080dd233aaae60fdafee196362ed5b6af7498e7ba07eaa725f0bc5a041016ce54a67d61b").unwrap();

        let data_package = DataPackage::new(
            vec![DataPoint::new("AVAX", "36.2488073814028")],
            1705311690000,
        );

        let allocated_signed_data_package = super::AllocatedSignedDataPackage::from_witness(
            cs,
            data_package,
            signature.try_into().unwrap(),
        )?;

        let is_valid = allocated_signed_data_package.check_by_address(cs, &address)?;
        assert!(is_valid.get_value().unwrap());

        Ok(())
    }
}
