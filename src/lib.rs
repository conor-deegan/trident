#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

//! # Usage
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! // NOTE: requires the `getrandom` feature
//! let (dk, ek) = trident::generate_key_pair();
//! let (ct, ss_sender) = ek.encapsulate();
//! let ss_receiver = dk.decapsulate(&ct);
//! assert_eq!(ss_sender, ss_receiver);
//! ```

mod error;

pub use crate::error::Error;
pub use rand_core::{CryptoRng, TryCryptoRng};

use core::fmt::{self, Debug};
use hqc_kem::{Hqc192, hqc192};
use ml_kem::{
    Decapsulate, KeyExport,
    array::{Array, sizes::U1088},
    ml_kem_768,
};
use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separation label. Used as a prefix for seed expansion and as a suffix in the combiner.
const LABEL: &[u8] = b"Trident-v1";

// Component sizes.
const MLKEM_EK_SIZE: usize = 1184;
const MLKEM_CT_SIZE: usize = 1088;
const X25519_SIZE: usize = 32;
const HQC_EK_SIZE: usize = hqc192::PUBLIC_KEY_SIZE;
const HQC_CT_SIZE: usize = hqc192::CIPHERTEXT_SIZE;
const HQC_M_SIZE: usize = hqc192::MESSAGE_SIZE;
const HQC_SALT_SIZE: usize = hqc192::SALT_SIZE;
/// HQC-192 code length `n` in bits. `pk_H = seed (32) || s`, where `s` packs `n` bits into
/// `ceil(n / 8)` bytes, leaving `8 - n % 8` unused high bits in the last byte.
const HQC_N: usize = 35851;
/// Bits of the last byte of `pk_H` that must be zero in a canonical encoding.
#[allow(clippy::cast_possible_truncation)]
const HQC_EK_PAD_MASK: u8 = 0xFF << (HQC_N % 8) as u32;
const _: () = assert!(HQC_EK_SIZE == 32 + HQC_N.div_ceil(8));

/// Size in bytes of a serialized [`EncapsulationKey`]: `pk_M (1184) || pk_X (32) || pk_H (4514)`.
pub const ENCAPSULATION_KEY_SIZE: usize = MLKEM_EK_SIZE + X25519_SIZE + HQC_EK_SIZE;
/// Size in bytes of a serialized [`DecapsulationKey`] (a seed).
pub const DECAPSULATION_KEY_SIZE: usize = 32;
/// Size in bytes of a serialized [`Ciphertext`]: `ct_M (1088) || ct_X (32) || ct_H (8978)`.
pub const CIPHERTEXT_SIZE: usize = MLKEM_CT_SIZE + X25519_SIZE + HQC_CT_SIZE;
/// Size in bytes of the shared key.
pub const SHARED_KEY_SIZE: usize = 32;
/// Number of uniformly random bytes consumed by one encapsulation:
/// `m_M (32) || ek_X (32) || m_H (24) || salt_H (16)`.
pub const ENCAPSULATION_RANDOMNESS_SIZE: usize = 32 + X25519_SIZE + HQC_M_SIZE + HQC_SALT_SIZE;

/// Shared key produced by encapsulation / decapsulation.
pub type SharedKey = [u8; SHARED_KEY_SIZE];

type MlKemDecapsulationKey = ml_kem_768::DecapsulationKey;
type MlKemEncapsulationKey = ml_kem_768::EncapsulationKey;
type MlKemCiphertext = Array<u8, U1088>;

// Naming follows the X-Wing draft:
//   ss -> shared secret, ct -> ciphertext, pk -> public key, sk -> secret key
//   _m -> ML-KEM-768, _x -> X25519, _h -> HQC-192

/// Generate a fresh Trident key pair using the system RNG.
///
/// # Panics
/// If the operating system RNG fails.
#[cfg(feature = "getrandom")]
#[must_use]
pub fn generate_key_pair() -> (DecapsulationKey, EncapsulationKey) {
    let dk = DecapsulationKey::generate();
    let ek = dk.encapsulation_key().clone();
    (dk, ek)
}

/// Generate a fresh Trident key pair using the provided RNG.
pub fn generate_key_pair_from_rng<R: CryptoRng + ?Sized>(
    rng: &mut R,
) -> (DecapsulationKey, EncapsulationKey) {
    let dk = DecapsulationKey::generate_from_rng(rng);
    let ek = dk.encapsulation_key().clone();
    (dk, ek)
}

/// Trident encapsulation (public) key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncapsulationKey {
    pk_m: MlKemEncapsulationKey,
    pk_x: PublicKey,
    pk_h: hqc192::EncapsulationKey,
}

impl EncapsulationKey {
    /// Parse an encapsulation key from its serialized form.
    ///
    /// # Errors
    /// Returns [`Error::InvalidKey`] if:
    /// - the ML-KEM-768 component fails the FIPS 203 modulus check, or
    /// - the HQC-192 component is not canonically encoded (any of the unused high bits of its
    ///   last byte are set). `hqc-kem` silently accepts these, which would let several distinct
    ///   byte strings act as the same HQC key; rejecting them keeps `ek` bytes and keys 1:1.
    pub fn from_bytes(bytes: &[u8; ENCAPSULATION_KEY_SIZE]) -> Result<Self, Error> {
        let (m, rest) = bytes.split_at(MLKEM_EK_SIZE);
        let (x, h) = rest.split_at(X25519_SIZE);

        // Public data: a variable-time check is fine here.
        if bytes[ENCAPSULATION_KEY_SIZE - 1] & HQC_EK_PAD_MASK != 0 {
            return Err(Error::InvalidKey);
        }

        let m: &Array<u8, _> = m.try_into().map_err(|_| Error::InvalidLength)?;
        let pk_m = MlKemEncapsulationKey::new(m).map_err(|_| Error::InvalidKey)?;
        let x: [u8; X25519_SIZE] = x.try_into().map_err(|_| Error::InvalidLength)?;
        let pk_x = PublicKey::from(x);
        let pk_h = hqc192::EncapsulationKey::try_from(h).map_err(|_| Error::InvalidLength)?;

        Ok(Self { pk_m, pk_x, pk_h })
    }

    /// Serialize as `pk_M || pk_X || pk_H`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ENCAPSULATION_KEY_SIZE] {
        let mut out = [0u8; ENCAPSULATION_KEY_SIZE];
        let (m, rest) = out.split_at_mut(MLKEM_EK_SIZE);
        let (x, h) = rest.split_at_mut(X25519_SIZE);
        m.copy_from_slice(&self.pk_m.to_bytes());
        x.copy_from_slice(self.pk_x.as_bytes());
        h.copy_from_slice(self.pk_h.as_ref());
        out
    }

    /// Encapsulate a fresh shared key using the system RNG.
    ///
    /// # Panics
    /// If the operating system RNG fails.
    #[cfg(feature = "getrandom")]
    #[must_use]
    pub fn encapsulate(&self) -> (Ciphertext, SharedKey) {
        self.encapsulate_with_rng(&mut rand_core::UnwrapErr(getrandom::SysRng))
    }

    /// Encapsulate a fresh shared key using the provided RNG.
    pub fn encapsulate_with_rng<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> (Ciphertext, SharedKey) {
        let mut randomness = [0u8; ENCAPSULATION_RANDOMNESS_SIZE];
        rng.fill_bytes(&mut randomness);
        let res = self.encapsulate_inner(&randomness);
        randomness.zeroize();
        res
    }

    /// Encapsulate with caller-supplied randomness, laid out as
    /// `m_M (32) || ek_X (32) || m_H (24) || salt_H (16)`. Intended for test vectors.
    ///
    /// # Warning
    /// Do NOT use this unless you know what you're doing. Reusing or biasing any of these bytes
    /// can be catastrophic.
    #[cfg(feature = "hazmat")]
    #[must_use]
    pub fn encapsulate_deterministic(
        &self,
        randomness: &[u8; ENCAPSULATION_RANDOMNESS_SIZE],
    ) -> (Ciphertext, SharedKey) {
        self.encapsulate_inner(randomness)
    }

    fn encapsulate_inner(
        &self,
        randomness: &[u8; ENCAPSULATION_RANDOMNESS_SIZE],
    ) -> (Ciphertext, SharedKey) {
        let (rand_m, rest) = randomness.split_at(32);
        let (rand_x, rest) = rest.split_at(X25519_SIZE);
        let (m_h, salt_h) = rest.split_at(HQC_M_SIZE);

        // ML-KEM-768
        let mut m_m = ml_kem::B32::default();
        m_m.copy_from_slice(rand_m);
        let (ct_m, mut ss_m) = self.pk_m.encapsulate_deterministic(&m_m);
        m_m.zeroize();

        // X25519: ct_X = X25519(ek_X, G), ss_X = X25519(ek_X, pk_X)
        let mut ek_x_bytes = [0u8; X25519_SIZE];
        ek_x_bytes.copy_from_slice(rand_x);
        let ek_x = StaticSecret::from(ek_x_bytes);
        ek_x_bytes.zeroize();
        let ct_x = PublicKey::from(&ek_x);
        let ss_x = ek_x.diffie_hellman(&self.pk_x);

        // HQC-192
        let mut salt = [0u8; HQC_SALT_SIZE];
        salt.copy_from_slice(salt_h);
        let (ct_h, ss_h) = self
            .pk_h
            .encapsulate_deterministic(m_h, &salt)
            .expect("HQC message length is fixed by ENCAPSULATION_RANDOMNESS_SIZE");
        salt.zeroize();

        let ss = combiner(
            ss_m.as_ref(),
            ss_x.as_bytes(),
            ss_h.as_ref(),
            &ct_x,
            &self.pk_x,
            ct_h.as_ref(),
            self.pk_h.as_ref(),
        );
        ss_m.zeroize();

        (Ciphertext { ct_m, ct_x, ct_h }, ss)
    }
}

impl TryFrom<&[u8]> for EncapsulationKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; ENCAPSULATION_KEY_SIZE] =
            bytes.try_into().map_err(|_| Error::InvalidLength)?;
        Self::from_bytes(bytes)
    }
}

/// Trident decapsulation (private) key.
///
/// Serialized as a 32-byte seed. The expanded component keys are cached so that decapsulation
/// does not have to rerun key generation (HQC key generation in particular is not cheap).
///
/// The X25519 component accepts non-contributory (all-zero) shared secrets, the default
/// behaviour of X-Wing. That component is only one of three, and the combiner binds
/// `ct_X` and `pk_X`, so decapsulation stays infallible.
#[derive(Clone)]
pub struct DecapsulationKey {
    seed: [u8; DECAPSULATION_KEY_SIZE],
    sk_m: MlKemDecapsulationKey,
    sk_x: StaticSecret,
    sk_h: hqc192::DecapsulationKey,
    ek: EncapsulationKey,
}

impl DecapsulationKey {
    /// Derive a decapsulation key from a 32-byte uniformly random seed.
    #[must_use]
    pub fn from_seed(seed: [u8; DECAPSULATION_KEY_SIZE]) -> Self {
        let (sk_m, sk_x, sk_h) = expand_seed(&seed);
        let ek = EncapsulationKey {
            pk_m: sk_m.encapsulation_key().clone(),
            pk_x: PublicKey::from(&sk_x),
            pk_h: sk_h.encapsulation_key().clone(),
        };
        Self {
            seed,
            sk_m,
            sk_x,
            sk_h,
            ek,
        }
    }

    /// Generate a fresh decapsulation key using the system RNG.
    ///
    /// # Panics
    /// If the operating system RNG fails.
    #[cfg(feature = "getrandom")]
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_from_rng(&mut rand_core::UnwrapErr(getrandom::SysRng))
    }

    /// Generate a fresh decapsulation key using the provided RNG.
    pub fn generate_from_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut seed = [0u8; DECAPSULATION_KEY_SIZE];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// Generate a fresh decapsulation key using the provided fallible RNG.
    ///
    /// # Errors
    /// Propagates any error from the RNG.
    pub fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut seed = [0u8; DECAPSULATION_KEY_SIZE];
        rng.try_fill_bytes(&mut seed)?;
        Ok(Self::from_seed(seed))
    }

    /// The 32-byte seed this key was derived from (its canonical serialization).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; DECAPSULATION_KEY_SIZE] {
        &self.seed
    }

    /// The matching encapsulation key.
    #[must_use]
    pub fn encapsulation_key(&self) -> &EncapsulationKey {
        &self.ek
    }

    /// Decapsulate a ciphertext. Never fails: each post-quantum component uses implicit
    /// rejection, so an invalid ciphertext yields a pseudorandom key.
    #[must_use]
    pub fn decapsulate(&self, ct: &Ciphertext) -> SharedKey {
        let mut ss_m = self.sk_m.decapsulate(&ct.ct_m);
        let ss_x = self.sk_x.diffie_hellman(&ct.ct_x);
        let ss_h = self.sk_h.decapsulate(&ct.ct_h);

        let ss = combiner(
            ss_m.as_ref(),
            ss_x.as_bytes(),
            ss_h.as_ref(),
            &ct.ct_x,
            &self.ek.pk_x,
            ct.ct_h.as_ref(),
            self.ek.pk_h.as_ref(),
        );
        ss_m.zeroize();
        ss
    }
}

impl From<[u8; DECAPSULATION_KEY_SIZE]> for DecapsulationKey {
    fn from(seed: [u8; DECAPSULATION_KEY_SIZE]) -> Self {
        Self::from_seed(seed)
    }
}

impl Debug for DecapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecapsulationKey")
            .field("ek", &self.ek)
            .finish_non_exhaustive()
    }
}

impl Drop for DecapsulationKey {
    fn drop(&mut self) {
        // The component secret keys zeroize themselves on drop.
        self.seed.zeroize();
    }
}

impl ZeroizeOnDrop for DecapsulationKey {}

/// Trident ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    ct_m: MlKemCiphertext,
    ct_x: PublicKey,
    ct_h: hqc192::Ciphertext,
}

impl Ciphertext {
    /// Parse a ciphertext from its serialized form `ct_M || ct_X || ct_H`.
    ///
    /// Any byte string of the right length is accepted.
    #[must_use]
    #[allow(clippy::missing_panics_doc)] // the HQC slice length is fixed by the array type
    pub fn from_bytes(bytes: &[u8; CIPHERTEXT_SIZE]) -> Self {
        let (m, rest) = bytes.split_at(MLKEM_CT_SIZE);
        let (x, h) = rest.split_at(X25519_SIZE);

        let mut ct_m = MlKemCiphertext::default();
        ct_m.copy_from_slice(m);
        let mut ct_x = [0u8; X25519_SIZE];
        ct_x.copy_from_slice(x);
        let ct_h = hqc192::Ciphertext::try_from(h).expect("HQC ciphertext length is fixed");

        Self {
            ct_m,
            ct_x: PublicKey::from(ct_x),
            ct_h,
        }
    }

    /// Serialize as `ct_M || ct_X || ct_H`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_SIZE] {
        let mut out = [0u8; CIPHERTEXT_SIZE];
        let (m, rest) = out.split_at_mut(MLKEM_CT_SIZE);
        let (x, h) = rest.split_at_mut(X25519_SIZE);
        m.copy_from_slice(&self.ct_m);
        x.copy_from_slice(self.ct_x.as_bytes());
        h.copy_from_slice(self.ct_h.as_ref());
        out
    }
}

impl TryFrom<&[u8]> for Ciphertext {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; CIPHERTEXT_SIZE] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        Ok(Self::from_bytes(bytes))
    }
}

/// Expand a 32-byte seed into the three component secret keys:
/// `SHAKE256(LABEL || seed)` -> `seed_M (64) || sk_X (32) || seed_H (32)`.
fn expand_seed(
    seed: &[u8; DECAPSULATION_KEY_SIZE],
) -> (
    MlKemDecapsulationKey,
    StaticSecret,
    hqc192::DecapsulationKey,
) {
    let mut xof = Shake256::default();
    xof.update(LABEL);
    xof.update(seed);
    let mut reader = xof.finalize_xof();

    let mut seed_m = ml_kem::Seed::default();
    reader.read(&mut seed_m);
    let mut sk_x = [0u8; X25519_SIZE];
    reader.read(&mut sk_x);
    let mut seed_h = [0u8; 32];
    reader.read(&mut seed_h);

    let sk_m = MlKemDecapsulationKey::from_seed(seed_m);
    let sk_x_secret = StaticSecret::from(sk_x);
    let (_pk_h, sk_h) = Hqc192::generate_key_deterministic(&seed_h);

    seed_m.zeroize();
    sk_x.zeroize();
    seed_h.zeroize();

    (sk_m, sk_x_secret, sk_h)
}

/// `SHA3-256(ss_M || ss_X || ss_H || ct_X || pk_X || ct_H || pk_H || LABEL)`
///
/// As in X-Wing, ML-KEM's ciphertext and public key are omitted: ML-KEM's FO transform already
/// binds them into `ss_M`. Unlike X-Wing, the full HQC ciphertext and public key are hashed
/// in too. So if HQC is the only component left standing, the combiner needs nothing beyond
/// HQC being IND-CCA2, with no ciphertext-binding assumption on HQC itself.
fn combiner(
    ss_m: &[u8],
    ss_x: &[u8; 32],
    ss_h: &[u8],
    ct_x: &PublicKey,
    pk_x: &PublicKey,
    ct_h: &[u8],
    pk_h: &[u8],
) -> SharedKey {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ss_h);
    Digest::update(&mut h, ct_x.as_bytes());
    Digest::update(&mut h, pk_x.as_bytes());
    Digest::update(&mut h, ct_h);
    Digest::update(&mut h, pk_h);
    Digest::update(&mut h, LABEL);
    h.finalize().into()
}

#[cfg(test)]
mod tests;
