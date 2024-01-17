use pairing::Engine;
use sync_vm::{
    circuit_structures::byte::{Byte, IntoBytes},
    franklin_crypto::{
        bellman::{plonk::better_better_cs::cs::ConstraintSystem, SynthesisError},
        plonk::circuit::boolean::Boolean,
    },
    traits::CSAllocatable,
    vm::primitives::uint256::UInt256,
};

use crate::gadgets::{ecdsa::Signature, ethereum::Address};

use super::types::{DataPackage, DataPoint};

pub struct CircuitDataPoint<E: Engine> {
    pub data_feed_id: [Byte<E>; 32],
    pub value: [Byte<E>; super::DEFAULT_NUM_VALUE_BS],
}

impl<E: Engine> CircuitDataPoint<E> {
    pub fn from_data_package<CS: ConstraintSystem<E>>(
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

pub struct CircuitSignedDataPackage<E: Engine> {
    pub data_package: CircuitDataPackage<E>,
    pub signature: Signature<E>,
}

impl<E: Engine> CircuitSignedDataPackage<E> {
    pub fn from_witness<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        data_package: DataPackage,
        signature: [u8; 65],
    ) -> Result<Self, SynthesisError> {
        let data_package = CircuitDataPackage::from_witness(cs, data_package)?;
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
        guardian_set: &[Address<E>],
    ) -> Result<Boolean, SynthesisError> {
        if guardian_set.is_empty() {
            return Ok(Boolean::Constant(false));
        }
        let (successful, (x, y)) = self.ecrecover(cs)?;

        let is_matched = {
            let (x, y) = (
                x.into_be_bytes(cs)?.try_into().unwrap(),
                y.into_be_bytes(cs)?.try_into().unwrap(),
            );
            let address = Address::from_pubkey(cs, &x, &y)?;
            let mut is_matched = Boolean::constant(false);
            for (_, guardian) in guardian_set.iter().enumerate() {
                let is_equal = guardian.equals(cs, &address)?;
                is_matched = Boolean::or(cs, &is_matched, &is_equal)?;
            }
            is_matched
        };

        let is_ok = Boolean::and(cs, &is_matched, &successful)?;
        Ok(is_ok)
    }
}

pub struct CircuitDataPackage<E: Engine> {
    pub data_points: Vec<CircuitDataPoint<E>>,
    pub timestamp: [Byte<E>; super::TIMESTAMP_BS],
    pub data_points_count: [Byte<E>; super::DATA_POINTS_COUNT_BS],
    pub default_data_point_value_byte_size: [Byte<E>; super::DATA_POINT_VALUE_BYTE_SIZE_BS],
}

impl<E: Engine> CircuitDataPackage<E> {
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
            .map(|data_point| CircuitDataPoint::from_data_package(cs, data_point))
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
    use sync_vm::franklin_crypto::bellman::SynthesisError;

    use crate::{
        redstone::types::{DataPackage, DataPoint},
        utils::testing::{bytes_assert_eq, create_test_constraint_system},
    };

    use super::CircuitDataPackage;

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
        let circuit_data_package = CircuitDataPackage::from_witness(cs, data_package)
            .expect("should create circuit data package");
        let hash = circuit_data_package.keccak256_hash(cs)?;
        bytes_assert_eq(
            &hash,
            "e27cdb508629d3bbbb93739f48f282e89374eb5ea105cf519abd68a249cc2070",
        );
        println!("DONE");
        Ok(())
    }

    #[test]
    fn test_check_by_address() -> Result<(), SynthesisError> {
        Ok(())
    }
}
