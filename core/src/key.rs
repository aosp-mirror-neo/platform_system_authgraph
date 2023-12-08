// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

//! Definitions related to different types of keys and other cryptographic artifacts.
use crate::arc;
use crate::error::Error;
use crate::traits::Rng;
use crate::FallibleAllocExt;
use crate::{ag_err, ag_verr};
use alloc::vec::Vec;
use authgraph_wire as wire;
use coset::{
    cbor, cbor::value::Value, iana, AsCborValue, CborSerializable, CoseError, CoseKey, Label,
};
use wire::ErrorCode;
use zeroize::ZeroizeOnDrop;

pub use wire::Key;

/// Length of an AES 256-bits key in bytes
pub const AES_256_KEY_LEN: usize = 32;

/// Length of a SHA 256 digest in bytes
pub const SHA_256_LEN: usize = 32;

/// AES key of 256 bits
#[derive(Clone, ZeroizeOnDrop)]
pub struct AesKey(pub [u8; AES_256_KEY_LEN]);

impl TryFrom<arc::ArcPayload> for AesKey {
    type Error = Error;
    fn try_from(payload: arc::ArcPayload) -> Result<AesKey, Self::Error> {
        if payload.0.len() != AES_256_KEY_LEN {
            return Err(ag_err!(
                InvalidSharedKeyArcs,
                "payload key has invalid length: {}",
                payload.0.len()
            ));
        }
        let mut key = AesKey([0; AES_256_KEY_LEN]);
        key.0.copy_from_slice(&payload.0);
        Ok(key)
    }
}

/// Size (in bytes) of a curve 25519 private key.
pub const CURVE25519_PRIV_KEY_LEN: usize = 32;

/// Version of the cert chain as per
/// hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/
/// ExplicitKeyDiceCertChain.cddl
pub const EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION: i32 = 1;

/// Version of the identity as per
/// hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/Identity.cddl
pub const IDENTITY_VERSION: i32 = 1;

/// EC key pair on P256 curve, created for ECDH.
pub struct EcExchangeKey {
    /// Public key
    pub pub_key: EcExchangeKeyPub,
    /// Private key
    pub priv_key: EcExchangeKeyPriv,
}

/// Public key of an EC key pair created for ECDH
#[derive(Clone)]
pub struct EcExchangeKeyPub(pub CoseKey);

/// Private key of an EC key pair created for ECDH.
/// It is up to the implementers of the AuthGraph traits to decide how to encode the private key.
#[derive(ZeroizeOnDrop)]
pub struct EcExchangeKeyPriv(pub Vec<u8>);

/// Shared secret agreed via ECDH
#[derive(ZeroizeOnDrop)]
pub struct EcdhSecret(pub Vec<u8>);

/// Pseudo random key of 256 bits that is output by extract/expand functions of key derivation
#[derive(ZeroizeOnDrop)]
pub struct PseudoRandKey(pub [u8; 32]);

/// A nonce of 16 bytes, used for key exchange
#[derive(Clone)]
pub struct Nonce16(pub [u8; 16]);

impl Nonce16 {
    /// Create a random nonce of 16 bytes
    pub fn new(rng: &dyn Rng) -> Self {
        let mut nonce = Nonce16([0u8; 16]);
        rng.fill_bytes(&mut nonce.0);
        nonce
    }
}

/// A nonce of 12 bytes, used for AES-GCM encryption
pub struct Nonce12(pub [u8; 12]);

impl Nonce12 {
    /// Create a random nonce of 12 bytes
    pub fn new(rng: &dyn Rng) -> Self {
        let mut nonce = Nonce12([0u8; 12]);
        rng.fill_bytes(&mut nonce.0);
        nonce
    }
}

impl TryFrom<&[u8]> for Nonce12 {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        if v.len() != 12 {
            return Err(ag_err!(InvalidSharedKeyArcs, "nonce has invalid length: {}", v.len()));
        }
        let mut nonce = Nonce12([0; 12]);
        nonce.0.copy_from_slice(v);
        Ok(nonce)
    }
}

/// Milliseconds since an epoch that is common between source and sink
pub struct MillisecondsSinceEpoch(pub i64);

/// Variants of EC private key used to create signature
#[derive(Clone, ZeroizeOnDrop)]
pub enum EcSignKey {
    /// On curve Ed25519
    Ed25519([u8; CURVE25519_PRIV_KEY_LEN]),
    /// On NIST curve P-256
    P256(Vec<u8>),
    /// On NIST curve P-384
    P384(Vec<u8>),
}

/// Variants of EC public key used to verify signature
#[derive(Clone, PartialEq)]
pub enum EcVerifyKey {
    /// On curve Ed25519
    Ed25519(CoseKey),
    /// On NIST curve P-256
    P256(CoseKey),
    /// On NIST curve P-384
    P384(CoseKey),
}

impl EcVerifyKey {
    /// Return the `CoseKey` contained in any variant of this enum.
    /// Assume that the `CoseKey` is checked for appropriate header parameters before it used for
    /// signature verifictation.
    pub fn get_key(self) -> CoseKey {
        match self {
            EcVerifyKey::Ed25519(k) | EcVerifyKey::P256(k) | EcVerifyKey::P384(k) => k,
        }
    }

    /// Return the Cose signing algorithm corresponds to the given public signing key.
    /// Assume that the `CoseKey` is checked for appropriate header parameters before it is used for
    /// signature verification.
    pub fn get_cose_sign_algorithm(&self) -> iana::Algorithm {
        match *self {
            EcVerifyKey::Ed25519(_) => iana::Algorithm::EdDSA,
            EcVerifyKey::P256(_) => iana::Algorithm::ES256,
            EcVerifyKey::P384(_) => iana::Algorithm::ES384,
        }
    }
}

/// HMAC key of 256 bits
#[derive(ZeroizeOnDrop)]
pub struct HmacKey(pub [u8; 32]);

/// Identity of an AuthGraph participant. The CDDL is listed in hardware/interfaces/security/
/// authgraph/aidl/android/hardware/security/Identity.cddl
#[derive(Clone, PartialEq)]
pub struct Identity {
    /// Version of the cddl
    pub version: i32,
    /// Certificate chain
    pub cert_chain: CertChain,
    /// Identity verification policy
    pub policy: Option<Policy>,
}

/// Certificate chain containing the public signing key. The CDDL is listed in
/// hardware/interfaces/security/authgraph/aidl/android/hardware/security/
/// authgraph/ExplicitKeyDiceCertChain.cddl
#[derive(Clone, PartialEq)]
pub struct CertChain {
    /// Version of the cddl
    pub version: i32,
    /// Root public key used to verify the signature in the first DiceChainEntry. If `cert_chain`
    /// is none, this is the key used to verify the signature created by the AuthGraph participant.
    pub root_key: EcVerifyKey,
    /// Dice certificate chain.
    pub dice_cert_chain: Option<Vec<DiceChainEntry>>,
}

/// An entry in the certificate chain.
/// TODO: add methods for CBOR encoding/decoding
#[derive(Clone, Eq, PartialEq)]
pub struct DiceChainEntry(pub Vec<u8>);

/// Identity verification policy specifying how to validate the certificate chain. The CDDL is
/// listed in hardware/interfaces/security/authgraph/aidl/android/hardware/security/authgraph/
/// DicePolicy.cddl
#[derive(Clone, Eq, PartialEq)]
pub struct Policy(pub Vec<u8>);

/// The output of identity verification.
pub enum IdentityVerificationDecision {
    /// The latest certificate chain is allowed by the identity verification policy, the identity
    /// owner is not updated
    Match,
    /// The latest certificate chain is not allowed by the identity verification policy
    Mismatch,
    /// The latest certificate chain is allowed by the identity verification policy and the identity
    /// owner is updated
    Updated,
}

/// The structure containing the inputs for the `salt` used in extracting a pseudo random key
/// from the Diffie-Hellman secret.
/// salt = bstr .cbor [
///     source_version:    int,
///     sink_ke_pub_key:   bstr .cbor PlainPubKey,
///     source_ke_pub_key: bstr .cbor PlainPubKey,
///     sink_ke_nonce:     bstr .size 16,
///     source_ke_nonce:   bstr .size 16,
///     sink_cert_chain:   bstr .cbor ExplicitKeyDiceCertChain,
///     source_cert_chain: bstr .cbor ExplicitKeyDiceCertChain,
/// ]
pub struct SaltInput {
    /// Version advertised by the source (P1).
    pub source_version: i32,
    /// Public key from sink for key exchange
    pub sink_ke_pub_key: EcExchangeKeyPub,
    /// Public key from source for ke exchange
    pub source_ke_pub_key: EcExchangeKeyPub,
    /// Nonce from sink for key exchange
    pub sink_ke_nonce: Nonce16,
    /// Nonce from source for key exchange
    pub source_ke_nonce: Nonce16,
    /// ExplicitKeyDiceCertChain of sink
    pub sink_cert_chain: CertChain,
    /// ExplicitKeyDiceCertChain of source
    pub source_cert_chain: CertChain,
}

/// The structure containing the inputs for the `session_id` computed during key agreement.
/// session_id = bstr .cbor [
///     sink_ke_nonce:     bstr .size 16,
///     source_ke_nonce:   bstr .size 16,
/// ]
pub struct SessionIdInput {
    /// Nonce from sink for key exchange
    pub sink_ke_nonce: Nonce16,
    /// Nonce from source for key exchange
    pub source_ke_nonce: Nonce16,
}

impl AsCborValue for Identity {
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let mut array = match value {
            Value::Array(a) if a.len() == 3 || a.len() == 2 => a,
            _ => {
                return Err(CoseError::UnexpectedItem("_", "array with two or three items"));
            }
        };
        // TODO: Assume policy is none for now
        let cert_chain = match array.remove(1) {
            Value::Bytes(cert_chain_encoded) => CertChain::from_slice(&cert_chain_encoded)?,
            _ => {
                return Err(CoseError::UnexpectedItem("_", "encoded CertChain"));
            }
        };
        let version: i32 = match array.remove(0) {
            Value::Integer(i) => i.try_into()?,
            _ => {
                return Err(CoseError::UnexpectedItem("_", "Integer"));
            }
        };
        Ok(Identity { version, cert_chain, policy: None })
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut array = Vec::<Value>::new();
        array.try_push(Value::Integer(self.version.into())).map_err(|_| CoseError::EncodeFailed)?;
        array
            .try_push(Value::Bytes(self.cert_chain.to_vec()?))
            .map_err(|_| CoseError::EncodeFailed)?;
        // TODO: encode policy if present
        Ok(Value::Array(array))
    }
}

impl CborSerializable for Identity {}

impl AsCborValue for CertChain {
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let mut array = match value {
            Value::Array(a) if a.len() == 3 || a.len() == 2 => a,
            _ => {
                return Err(CoseError::UnexpectedItem("_", "array with two or three items"));
            }
        };
        // TODO: Assume `dice_cert_chain` is none for now
        let root_cose_key = match array.remove(1) {
            Value::Bytes(root_key_encoded) => CoseKey::from_slice(&root_key_encoded)?,
            _ => {
                return Err(CoseError::UnexpectedItem("_", "encoded CoseKey"));
            }
        };
        let version: i32 = match array.remove(0) {
            Value::Integer(i) => i.try_into()?,
            _ => {
                return Err(CoseError::UnexpectedItem("_", "Integer"));
            }
        };
        // TODO: Assume p256 for now and support other curve types later
        Ok(CertChain { version, root_key: EcVerifyKey::P256(root_cose_key), dice_cert_chain: None })
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut array = Vec::<Value>::new();
        array.try_push(Value::Integer(self.version.into())).map_err(|_| CoseError::EncodeFailed)?;
        array
            .try_push(Value::Bytes(self.root_key.get_key().to_vec()?))
            .map_err(|_| CoseError::EncodeFailed)?;
        // TODO: encode cert_chain if present
        Ok(Value::Array(array))
    }
}

impl CborSerializable for CertChain {}

impl AsCborValue for SaltInput {
    fn from_cbor_value(_value: Value) -> Result<Self, CoseError> {
        // This method will never be called, except (maybe) in case of unit testing
        Err(CoseError::EncodeFailed)
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut array = Vec::<Value>::new();
        array.try_reserve(7).map_err(|_| CoseError::EncodeFailed)?;
        array.push(Value::Integer(self.source_version.into()));
        array.push(Value::Bytes(self.sink_ke_pub_key.0.to_vec()?));
        array.push(Value::Bytes(self.source_ke_pub_key.0.to_vec()?));
        array.push(Value::Bytes(self.sink_ke_nonce.0.to_vec()));
        array.push(Value::Bytes(self.source_ke_nonce.0.to_vec()));
        array.push(Value::Bytes(self.sink_cert_chain.to_vec()?));
        array.push(Value::Bytes(self.source_cert_chain.to_vec()?));
        Ok(Value::Array(array))
    }
}

impl CborSerializable for SaltInput {}

impl AsCborValue for SessionIdInput {
    fn from_cbor_value(_value: Value) -> Result<Self, CoseError> {
        // This method will never be called, except (maybe) in case of unit testing
        Err(CoseError::EncodeFailed)
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut array = Vec::<Value>::new();
        array.try_reserve(2).map_err(|_| CoseError::EncodeFailed)?;
        array.push(Value::Bytes(self.sink_ke_nonce.0.to_vec()));
        array.push(Value::Bytes(self.source_ke_nonce.0.to_vec()));
        Ok(Value::Array(array))
    }
}

impl CborSerializable for SessionIdInput {}

/// Given a `CoseKey` and the set of expected parameters, check if the `CoseKey` contains them.
pub fn check_cose_key_params(
    cose_key: &coset::CoseKey,
    want_kty: iana::KeyType,
    want_alg: iana::Algorithm,
    want_curve: iana::EllipticCurve,
    err_code: ErrorCode,
) -> Result<(), Error> {
    if cose_key.kty != coset::KeyType::Assigned(want_kty) {
        return Err(ag_verr!(err_code, "invalid kty {:?}, expect {want_kty:?}", cose_key.kty));
    }
    if cose_key.alg != Some(coset::Algorithm::Assigned(want_alg)) {
        return Err(ag_verr!(err_code, "invalid alg {:?}, expect {want_alg:?}", cose_key.alg));
    }
    let curve = cose_key
        .params
        .iter()
        .find_map(|(l, v)| match (l, v) {
            (Label::Int(l), Value::Integer(v)) if *l == iana::Ec2KeyParameter::Crv as i64 => {
                Some(*v)
            }
            _ => None,
        })
        .ok_or_else(|| ag_verr!(err_code, "no curve"))?;
    if curve != cbor::value::Integer::from(want_curve as u64) {
        return Err(ag_verr!(err_code, "invalid curve {curve:?}, expect {want_curve:?}"));
    }
    Ok(())
}
