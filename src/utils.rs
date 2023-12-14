use pairing::Engine;
use sync_vm::circuit_structures::byte::Byte;
use sync_vm::franklin_crypto::bellman::SynthesisError;

pub fn new_synthesis_error<T: ToString>(msg: T) -> SynthesisError {
    let err = std::io::Error::new(std::io::ErrorKind::Other, msg.to_string());
    SynthesisError::from(err)
}

#[cfg(test)]
pub fn bytes_assert_eq<E: Engine>(bytes: &[Byte<E>], expected_hex: &str) {
    let bytes = bytes
        .into_iter()
        .map(|b| b.get_byte_value().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(hex::encode(&bytes), expected_hex);
}

pub fn hex_to_bytes_constant<E: Engine>(hex_str: &str) -> Result<Vec<Byte<E>>, SynthesisError> {
    let bytes = hex::decode(hex_str)
        .map_err(new_synthesis_error)?
        .into_iter()
        .map(|b| Byte::<E>::constant(b))
        .collect::<Vec<_>>();
    Ok(bytes)
}
