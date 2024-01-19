use std::{str::FromStr, usize};

use bigdecimal::{BigDecimal, RoundingMode};
use num_bigint::ToBigInt;

use super::{
    DATA_POINTS_COUNT_BS, DATA_POINT_VALUE_BYTE_SIZE_BS, DEFAULT_NUM_VALUE_BS,
    DEFAULT_NUM_VALUE_DECIMALS, TIMESTAMP_BS,
};

#[derive(Clone, Debug)]
pub struct DataPoint {
    pub data_feed_id: String,
    pub value: String,
}

impl DataPoint {
    pub fn new<T: ToString, U: ToString>(data_feed_id: T, value: U) -> Self {
        Self {
            data_feed_id: data_feed_id.to_string(),
            value: value.to_string(),
        }
    }

    pub fn serialize_feed_id(&self) -> Vec<u8> {
        convert_string_to_bytes32(&self.data_feed_id)
            .as_slice()
            .to_vec()
    }

    pub fn serialize_value(&self) -> Vec<u8> {
        convert_number_to_bytes32(&self.value, DEFAULT_NUM_VALUE_DECIMALS as u8)
            .as_slice()
            .to_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let bytes_data_feed_id = self.serialize_feed_id();
        let bytes_value = self.serialize_value();
        bytes.extend(bytes_data_feed_id);
        bytes.extend(bytes_value);
        bytes
    }
}

#[derive(Clone, Debug)]
pub struct DataPackage {
    pub data_points: Vec<DataPoint>,
    pub timestamp: u64,
}

impl DataPackage {
    pub fn new(data_points: Vec<DataPoint>, timestamp: u64) -> Self {
        Self {
            data_points,
            timestamp,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.serialize_data_points());
        bytes.extend(self.serialize_timestamp());
        bytes.extend(self.serialize_default_data_point_byte_size());
        bytes.extend(self.serialize_data_points_count());
        bytes
    }

    pub fn sorted_data_points(&self) -> Vec<DataPoint> {
        let mut data_points = self.data_points.clone();
        data_points.sort_by(|a, b| {
            let a_id = a.serialize_feed_id();
            let b_id = b.serialize_feed_id();
            a_id.cmp(&b_id)
        });
        data_points
    }

    pub fn serialize_data_points(&self) -> Vec<u8> {
        let data_points = self.sorted_data_points();
        let mut bytes = vec![];
        for data_point in data_points.iter() {
            bytes.extend(data_point.serialize());
        }
        bytes
    }

    pub fn serialize_timestamp(&self) -> Vec<u8> {
        convert_number_to_bytes::<_, TIMESTAMP_BS>(self.timestamp, 0)
            .as_slice()
            .to_vec()
    }

    pub fn serialize_data_points_count(&self) -> Vec<u8> {
        convert_number_to_bytes::<_, DATA_POINTS_COUNT_BS>(self.data_points.len(), 0)
            .as_slice()
            .to_vec()
    }

    pub fn serialize_default_data_point_byte_size(&self) -> Vec<u8> {
        convert_number_to_bytes::<_, DATA_POINT_VALUE_BYTE_SIZE_BS>(DEFAULT_NUM_VALUE_BS, 0)
            .as_slice()
            .to_vec()
    }
}

type Bytes32 = [u8; 32];

pub fn convert_string_to_bytes32<T: ToString>(str: T) -> Bytes32 {
    let str = str.to_string();
    if str.len() > 31 {
        panic!("String too long to convert to bytes32")
    }
    let bytes = str.as_bytes();
    let mut ret = [0u8; 32];
    ret[..bytes.len()].copy_from_slice(bytes);
    ret
}

pub fn convert_number_to_bytes32<T: ToString>(number: T, decimals: u8) -> Bytes32 {
    convert_number_to_bytes::<T, 32>(number, decimals)
}

pub fn convert_number_to_bytes<T: ToString, const N: usize>(number: T, decimals: u8) -> [u8; N] {
    let number = BigDecimal::from_str(&number.to_string())
        .unwrap()
        .with_scale_round(decimals as i64, RoundingMode::Down);
    let number = {
        let number = number * 10u64.checked_pow(decimals.into()).unwrap();
        let bigint = number.to_bigint().unwrap();
        bigint.to_biguint().unwrap()
    };
    let bytes = number.to_bytes_be();
    let mut ret = [0u8; N];
    ret[(N - bytes.len())..].copy_from_slice(bytes.as_slice());
    ret
}

#[cfg(test)]
mod tests {
    use crate::redstone::witness::{
        convert_number_to_bytes32, convert_string_to_bytes32, DataPackage, DataPoint,
    };

    #[test]
    fn test_convert_number_to_bytes() -> anyhow::Result<()> {
        let bytes = convert_number_to_bytes32("42.1234567", 10);
        assert_eq!(
            hex::encode(bytes),
            "0000000000000000000000000000000000000000000000000000006213896758",
        );
        Ok(())
    }

    #[test]
    fn test_convert_string_to_bytes32() -> anyhow::Result<()> {
        let bytes = convert_string_to_bytes32("BTC");
        assert_eq!(
            hex::encode(bytes),
            "4254430000000000000000000000000000000000000000000000000000000000"
        );
        Ok(())
    }

    #[test]
    // Case reference:
    // https://github.com/redstone-finance/redstone-oracles-monorepo/blob/cd0a6ffffbfcb1fb3dbf255b9d599db26e3faf34/packages/protocol/test/plain-obj-serialization.test.ts#L86
    fn test_data_points_as_bytes() -> anyhow::Result<()> {
        let data_package = DataPackage::new(
            vec![
                DataPoint::new("BTC", "20000"),
                DataPoint::new("ETH", "1000"),
            ],
            1654353400000u64,
        );
        let bytes = data_package.serialize();
        assert_eq!(
            hex::encode(&bytes),
            "4254430000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d1a94a20004554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000174876e80001812f2590c000000020000002"
        );

        use sha3::{Digest, Keccak256};
        let mut hasher = <Keccak256 as Digest>::new();
        Digest::update(&mut hasher, &bytes);
        let hash = Digest::finalize(hasher);
        assert_eq!(
            hex::encode(hash),
            "e27cdb508629d3bbbb93739f48f282e89374eb5ea105cf519abd68a249cc2070",
        );

        use secp256k1::{Message, Secp256k1, SecretKey};
        let seckey = SecretKey::from_slice(
            &hex::decode("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
        )
        .unwrap();
        let secp = Secp256k1::new();
        let msg = { Message::from_digest_slice(hash.as_ref()).unwrap() };
        let recoverable_signature = secp.sign_ecdsa_recoverable(&msg, &seckey);
        let (recid, signature_bytes) = recoverable_signature.serialize_compact();

        let mut bytes = vec![];
        bytes.extend(signature_bytes);
        // Ethereum adds 27 to the recovery id to get the v value
        bytes.push(recid.to_i32() as u8 + 27);
        use base64::prelude::*;
        let base64_str = BASE64_STANDARD.encode(&bytes);
        assert_eq!("NX5yd/Cs8HzVdNchrM59uOoSst7n9KK5Ou9pA6S5GTM0RwghGlFjA0S+SVfb85ipg4HzUTKATBZSqPXlWldEEhw=", base64_str);

        Ok(())
    }

    #[test]
    fn test_decimal_value() -> anyhow::Result<()> {
        use secp256k1::{
            ecdsa::{RecoverableSignature, RecoveryId},
            Message,
        };

        let data_package = DataPackage::new(
            vec![DataPoint::new("AVAX", "36.2488073814028")],
            1705311690000,
        );
        let bytes = data_package.serialize();
        println!("serialized bytes: {}", hex::encode(&bytes),);

        use sha3::{Digest, Keccak256};
        let mut hasher = <Keccak256 as Digest>::new();
        Digest::update(&mut hasher, &bytes);
        let hash = Digest::finalize(hasher);
        println!("hash: {}", hex::encode(hash),);

        use base64::prelude::*;
        let signatures = BASE64_STANDARD.decode("mtH5bAg88x91ezOw72ssQnlYm/BInBw6e+sABdIIDdIzqq5g/a/uGWNi7Vtq90mOe6B+qnJfC8WgQQFs5Upn1hs=").unwrap();
        println!("signature: {}", hex::encode(&signatures));

        // Ethereum adds 27 to the recovery id to get the v value
        let rec_id = RecoveryId::from_i32(signatures[64] as i32 - 27).unwrap();
        let recoverable_signature =
            RecoverableSignature::from_compact(&signatures[..64], rec_id).unwrap();
        let message = Message::from_digest_slice(hash.as_ref()).unwrap();
        let pubkey = recoverable_signature.recover(&message).unwrap();

        let mut hasher = <Keccak256 as Digest>::new();
        Digest::update(&mut hasher, &pubkey.serialize_uncompressed()[1..]);
        let recovered_addr = &Digest::finalize(hasher)[12..];

        let expected_addr = hex::decode("109B4a318A4F5ddcbCA6349B45f881B4137deaFB").unwrap();
        assert_eq!(expected_addr, recovered_addr);

        Ok(())
    }
}
