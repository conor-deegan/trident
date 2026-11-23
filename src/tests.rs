#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

extern crate std;
use super::*;
use rand_core::TryRng;
use shake::Shake256Reader;
use std::string::ToString;

/// Deterministic SHAKE256-based RNG for tests.
struct TestRng(Shake256Reader);

impl TestRng {
    fn new(label: &[u8]) -> Self {
        let mut x = Shake256::default();
        x.update(label);
        Self(x.finalize_xof())
    }
}

impl TryRng for TestRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.0.read(&mut b);
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.0.read(&mut b);
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read(dst);
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

fn sha3(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}

#[test]
fn sizes() {
    assert_eq!(ENCAPSULATION_KEY_SIZE, 5730);
    assert_eq!(CIPHERTEXT_SIZE, 10098);
    assert_eq!(ENCAPSULATION_RANDOMNESS_SIZE, 104);
}

#[test]
fn round_trip() {
    let mut rng = TestRng::new(b"round_trip");
    for _ in 0..8 {
        let (dk, ek) = generate_key_pair_from_rng(&mut rng);
        let (ct, ss1) = ek.encapsulate_with_rng(&mut rng);
        assert_eq!(ss1, dk.decapsulate(&ct));
    }
}

#[test]
fn serialization_round_trip() {
    let mut rng = TestRng::new(b"serialization");
    let (dk, ek) = generate_key_pair_from_rng(&mut rng);

    let ek2 = EncapsulationKey::from_bytes(&ek.to_bytes()).unwrap();
    assert_eq!(ek, ek2);

    let dk2 = DecapsulationKey::from_seed(*dk.as_bytes());
    assert_eq!(dk.encapsulation_key(), dk2.encapsulation_key());

    let (ct, ss) = ek2.encapsulate_with_rng(&mut rng);
    let ct2 = Ciphertext::from_bytes(&ct.to_bytes());
    assert_eq!(ct, ct2);
    assert_eq!(ss, dk2.decapsulate(&ct2));

    assert_eq!(
        EncapsulationKey::try_from(&ek.to_bytes()[1..]),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        Ciphertext::try_from(&ct.to_bytes()[1..]),
        Err(Error::InvalidLength)
    );
}

#[test]
fn rejects_invalid_mlkem_key() {
    let mut rng = TestRng::new(b"invalid");
    let (_, ek) = generate_key_pair_from_rng(&mut rng);
    let mut bytes = ek.to_bytes();
    // First ML-KEM coefficient = 0xFFF >= q fails the FIPS 203 modulus check.
    bytes[0] = 0xFF;
    bytes[1] |= 0x0F;
    assert_eq!(EncapsulationKey::from_bytes(&bytes), Err(Error::InvalidKey));
}

#[test]
fn rejects_noncanonical_hqc_key() {
    let mut rng = TestRng::new(b"noncanonical");
    // Honest keys are always canonical.
    for _ in 0..16 {
        let (_, ek) = generate_key_pair_from_rng(&mut rng);
        assert!(EncapsulationKey::from_bytes(&ek.to_bytes()).is_ok());
    }
    let (_, ek) = generate_key_pair_from_rng(&mut rng);
    let bytes = ek.to_bytes();
    // n = 35851, so bits 3..=7 of the last byte are padding.
    for bit in 3..8 {
        let mut b = bytes;
        b[ENCAPSULATION_KEY_SIZE - 1] |= 1 << bit;
        assert_eq!(
            EncapsulationKey::from_bytes(&b),
            Err(Error::InvalidKey),
            "bit {bit}"
        );
    }
    // A real coefficient bit in the last byte is fine.
    let mut b = bytes;
    b[ENCAPSULATION_KEY_SIZE - 1] ^= 1;
    assert!(EncapsulationKey::from_bytes(&b).is_ok());
}

/// Flipping a bit in any component's ciphertext must change the decapsulated key.
#[test]
fn tamper_each_component() {
    let mut rng = TestRng::new(b"tamper");
    let (dk, ek) = generate_key_pair_from_rng(&mut rng);
    let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
    let bytes = ct.to_bytes();

    for (name, offset) in [
        ("ML-KEM", 0),
        ("X25519", MLKEM_CT_SIZE),
        ("HQC", MLKEM_CT_SIZE + X25519_SIZE),
        ("HQC salt", CIPHERTEXT_SIZE - 1),
    ] {
        let mut t = bytes;
        t[offset] ^= 1;
        let ss_t = dk.decapsulate(&Ciphertext::from_bytes(&t));
        assert_ne!(ss, ss_t, "tampering {name} did not change the key");
    }
}

/// Rebuild the shared key by hand from the upstream crates and check it matches what Trident's
/// own code produces, which catches mistakes in how the pieces are wired together.
#[test]
fn matches_manual_construction() {
    let seed = [7u8; 32];
    let randomness: [u8; ENCAPSULATION_RANDOMNESS_SIZE] = core::array::from_fn(|i| i as u8);

    // Seed expansion: SHAKE256("Trident-v1" || seed) -> 64 || 32 || 32
    let mut xof = Shake256::default();
    xof.update(b"Trident-v1");
    xof.update(&seed);
    let mut expanded = [0u8; 128];
    xof.finalize_xof().read(&mut expanded);

    let sk_m = ml_kem_768::DecapsulationKey::from_seed(Array::try_from(&expanded[..64]).unwrap());
    let sk_x = StaticSecret::from(<[u8; 32]>::try_from(&expanded[64..96]).unwrap());
    let (pk_h, _sk_h) = Hqc192::generate_key_deterministic(&expanded[96..128].try_into().unwrap());
    let pk_m = sk_m.encapsulation_key().clone();
    let pk_x = PublicKey::from(&sk_x);

    // Component encapsulations with the documented randomness split.
    let (ct_m, ss_m) = pk_m.encapsulate_deterministic(&Array::try_from(&randomness[..32]).unwrap());
    let ek_x = StaticSecret::from(<[u8; 32]>::try_from(&randomness[32..64]).unwrap());
    let ct_x = PublicKey::from(&ek_x);
    let ss_x = ek_x.diffie_hellman(&pk_x);
    let (ct_h, ss_h) = pk_h
        .encapsulate_deterministic(
            &randomness[64..88],
            &randomness[88..104].try_into().unwrap(),
        )
        .unwrap();

    let mut transcript = [0u8; 32 * 5 + HQC_CT_SIZE + HQC_EK_SIZE + 10];
    let mut off = 0;
    for part in [
        ss_m.as_slice(),
        ss_x.as_bytes(),
        ss_h.as_ref(),
        ct_x.as_bytes(),
        pk_x.as_bytes(),
        ct_h.as_ref(),
        pk_h.as_ref(),
        b"Trident-v1",
    ] {
        transcript[off..off + part.len()].copy_from_slice(part);
        off += part.len();
    }
    assert_eq!(off, transcript.len());
    let expected_ss = sha3(&transcript);

    // Now via Trident.
    let dk = DecapsulationKey::from_seed(seed);
    let ek = dk.encapsulation_key();
    let (ct, ss) = ek.encapsulate_inner(&randomness);
    assert_eq!(ss, expected_ss);
    assert_eq!(dk.decapsulate(&ct), expected_ss);

    // Wire format.
    let ek_bytes = ek.to_bytes();
    assert_eq!(&ek_bytes[..1184], pk_m.to_bytes().as_slice());
    assert_eq!(&ek_bytes[1184..1216], pk_x.as_bytes());
    assert_eq!(&ek_bytes[1216..], pk_h.as_ref());
    let ct_bytes = ct.to_bytes();
    assert_eq!(&ct_bytes[..1088], ct_m.as_slice());
    assert_eq!(&ct_bytes[1088..1120], ct_x.as_bytes());
    assert_eq!(&ct_bytes[1120..], ct_h.as_ref());
}

/// Pinned regression vectors. If any of these change, the wire format or derivation changed.
///
/// Each entry: (seed, encapsulation randomness, SHA3-256(ek), SHA3-256(ct), ss).
type Vector = (
    [u8; 32],
    [u8; ENCAPSULATION_RANDOMNESS_SIZE],
    &'static str,
    &'static str,
    &'static str,
);

#[test]
fn regression_vectors() {
    let vectors: [Vector; 3] = [
        (
            core::array::from_fn(|i| i as u8),
            core::array::from_fn(|i| (0xA0 + i) as u8),
            "6aefbeccd8bc2edf1b64bde2ad78e21143d352f5c67ec452868ccec152c09eaf",
            "dc5050997e72478efd288711f940da78da573922bf314f9e259c5025ee34b380",
            "f773cc02b95806627052efd1df79328681a6fa251fbae5cb38c0cc6e0e0b75b6",
        ),
        (
            [0x00; 32],
            [0x00; ENCAPSULATION_RANDOMNESS_SIZE],
            "abcfd897d11c4a2776867d7e400c3fe775ea8098efce1a9a4d32ec291d4df15d",
            "5cc21684b9f7f15335c3ab81b56f6522e831dfc615f9c4a900922f9367495f17",
            "65cd4a654692eb8e66ed6b7b95bcfa4b8064210619ff993e040913be341252d2",
        ),
        (
            [0xFF; 32],
            [0xFF; ENCAPSULATION_RANDOMNESS_SIZE],
            "bc47e37d2ef7284c13e5cfa550dead37dcb1c91463666015caa7df48e1f352a8",
            "102a78d9b0907b0043e4351cb20d0a98c0aa177ffef1faff0948349d1d25f664",
            "219a01ffe264c2bf090136516ca37426b3d8ed7a373bbd3c1a0b0c5c0233d5cc",
        ),
    ];

    for (i, (seed, randomness, ek_hash, ct_hash, ss_hex)) in vectors.iter().enumerate() {
        let dk = DecapsulationKey::from_seed(*seed);
        let ek = dk.encapsulation_key();
        let (ct, ss) = ek.encapsulate_inner(randomness);
        assert_eq!(dk.decapsulate(&ct), ss);

        let got = (
            hex::encode(sha3(&ek.to_bytes())),
            hex::encode(sha3(&ct.to_bytes())),
            hex::encode(ss),
        );
        let expected = (ek_hash.to_string(), ct_hash.to_string(), ss_hex.to_string());
        assert_eq!(got, expected, "vector {i}: {got:#?}");
    }
}

/// Pins decapsulation of a ciphertext whose X25519 part is the all-zero (low-order) point, so
/// the "accept non-contributory" behaviour is fixed and testable by other implementations.
#[test]
fn regression_non_contributory() {
    let dk = DecapsulationKey::from_seed([0x42; 32]);
    let (ct, ss) = dk
        .encapsulation_key()
        .encapsulate_inner(&[0x24; ENCAPSULATION_RANDOMNESS_SIZE]);
    let mut bytes = ct.to_bytes();
    bytes[MLKEM_CT_SIZE..MLKEM_CT_SIZE + X25519_SIZE].fill(0);
    let ss_zero = dk.decapsulate(&Ciphertext::from_bytes(&bytes));

    assert_ne!(ss, ss_zero);
    assert_eq!(
        hex::encode(ss_zero),
        "004e8c622b7b3a78dfa849beaf6e2d43832ce77e0fa05c1a4eb9ade3b88ea13e"
    );
}
