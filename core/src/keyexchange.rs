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

//! Authenticated Key Exchange (AKE) related operations. AKE is executed between two parties P1
//! (source) and P2 (sink).
use crate::{
    ag_err, arc,
    arc::ArcPayload,
    error::Error,
    key::{
        check_cose_key_params, AesKey, EcExchangeKey, EcExchangeKeyPriv, EcExchangeKeyPub,
        EcSignKey, EcVerifyKey, EcdhSecret, HmacKey, Identity, Key, Nonce16, PseudoRandKey,
        SaltInput, SessionIdInput,
    },
    traits::{EcDh, EcDsa, Hkdf, Sha256, TraitImpl},
    try_to_vec, FallibleAllocExt,
};
use alloc::vec::Vec;
use authgraph_wire as wire;
use core::mem::take;
use coset::{
    cbor::value::Value, iana, AsCborValue, CborSerializable, CoseKey, CoseSign1, CoseSign1Builder,
    HeaderBuilder, Label,
};
use wire::ErrorCode;

pub use wire::{KeInitResult, SessionInfo, SessionInitiationInfo};

/// Context for deriving the first shared encryption key
pub const CONTEXT_KE_ENCRYPTION_KEY_1: &[u8] = b"KE_FIRST_ENCRYPTION_KEY";
/// Context for deriving the second shared encryption key
pub const CONTEXT_KE_ENCRYPTION_KEY_2: &[u8] = b"KE_SECOND_ENCRYPTION_KEY";
/// Context for deriving the shared HMAC key
pub const CONTEXT_KE_HMAC_KEY: &[u8] = b"KE_HMAC_KEY";

/// Enum defining the roles played by the two AuthGraph participants
pub enum Role {
    /// AuthGraph source
    Source = 1,
    /// AuthGraph sink
    Sink = 2,
}

/// This method is invoked on P1 (source).
/// Creates an ephemeral EC key pair for ECDH and a nonce (16 bytes).
pub fn create(imp: &mut TraitImpl) -> Result<SessionInitiationInfo, Error> {
    // Create an EC key for ECDH
    let EcExchangeKey { pub_key: pub_key_for_ecdh, priv_key: mut priv_key_for_ecdh } =
        imp.ecdh.generate_key()?;
    // Create a nonce for key agreement
    let nonce_for_ke = Nonce16::new(&mut *imp.rng);

    let pbk = imp.device.get_or_create_per_boot_key(&*imp.aes_gcm, &mut *imp.rng)?;
    let mut protected_headers = Vec::<(Label, Value)>::new();
    protected_headers.try_push((arc::KE_NONCE, Value::Bytes(nonce_for_ke.0.clone().to_vec())))?;
    let priv_key_arc = arc::create_arc(
        &pbk,
        arc::ArcContent {
            payload: ArcPayload(take(&mut priv_key_for_ecdh.0)),
            protected_headers,
            ..Default::default()
        },
        &*imp.aes_gcm,
        &mut *imp.rng,
    )?;
    let (_sign_key, identity) = imp.device.get_identity()?;
    Ok(SessionInitiationInfo {
        ke_key: Key {
            pub_key: Some(pub_key_for_ecdh.0.to_vec()?),
            arc_from_pbk: Some(priv_key_arc),
        },
        identity: identity.to_vec()?,
        nonce: nonce_for_ke.0.to_vec(),
        version: imp.device.get_source_version(),
    })
}

/// This method is invoked on P2 (sink).
/// This is the second step in the key exchange protocol.
pub fn init(
    imp: &mut TraitImpl,
    peer_key: &[u8],
    peer_id: &[u8],
    peer_nonce: &[u8],
    peer_version: i32,
) -> Result<KeInitResult, Error> {
    if imp.device.get_sink_version(peer_version) > peer_version {
        ag_err!(InternalError, "protocol version is greater than peer's version");
    }
    let key_for_ecdh = imp.ecdh.generate_key()?;
    let own_nonce = Nonce16::new(&mut *imp.rng);

    let (peer_pub_key, peer_identity, peer_nonce) =
        decode_peer_info(peer_key, peer_id, peer_nonce)?;

    let ecdh_secret = compute_shared_secret(&*imp.ecdh, &key_for_ecdh.priv_key, &peer_pub_key)?;
    let (sign_key, own_identity) = imp.device.get_identity()?;

    let salt_input = SaltInput {
        source_version: peer_version,
        sink_ke_pub_key: key_for_ecdh.pub_key.clone(),
        source_ke_pub_key: peer_pub_key,
        sink_ke_nonce: own_nonce.clone(),
        source_ke_nonce: peer_nonce.clone(),
        sink_cert_chain: own_identity.cert_chain.clone(),
        source_cert_chain: peer_identity.cert_chain.clone(),
    };

    let salt = compute_salt(salt_input, &*imp.sha256)?;
    let (in_encrypt_key, out_encrypt_key, hmac_key) =
        derive_shared_keys(&ecdh_secret, &salt, Role::Sink, &*imp.hkdf)?;

    let (session_id, signature) = compute_sign_session_id(
        SessionIdInput { sink_ke_nonce: own_nonce.clone(), source_ke_nonce: peer_nonce },
        HmacKey(hmac_key.0),
        sign_key,
        imp,
    )?;

    // create two arcs encrypting the two shared encrypting keys with the per-boot-key
    let shared_keys = create_shared_key_arcs(
        own_identity.clone(),
        peer_identity,
        AesKey(in_encrypt_key.0),
        AesKey(out_encrypt_key.0),
        &session_id,
        arc::AuthenticationCompleted(false),
        imp,
    )?;

    Ok(KeInitResult {
        session_init_info: SessionInitiationInfo {
            ke_key: Key { pub_key: Some(key_for_ecdh.pub_key.0.to_vec()?), arc_from_pbk: None },
            identity: own_identity.to_vec()?,
            nonce: own_nonce.0.to_vec(),
            version: imp.device.get_sink_version(peer_version),
        },
        session_info: SessionInfo { shared_keys, session_id, session_id_signature: signature },
    })
}

/// This method is invoked on P1 (source)
/// This is the third step in the key exchange protocol.
pub fn finish(
    imp: &mut TraitImpl,
    peer_key: &[u8],
    peer_id: &[u8],
    peer_sig: &[u8],
    peer_nonce: &[u8],
    peer_version: i32,
    own_ke_key: Key,
) -> Result<SessionInfo, Error> {
    if imp.device.get_source_version() < peer_version {
        ag_err!(IncompatibleProtocolVersion, "peer's protocol version is incompatible");
    }
    let pbk = imp.device.get_per_boot_key()?;
    let mut own_ke_key_arc_content = arc::decipher_arc(
        &pbk,
        &own_ke_key.arc_from_pbk.ok_or(ag_err!(InvalidPrivKeyArcInKey, "missing priv key arc"))?,
        &*imp.aes_gcm,
    )?;

    let own_ke_nonce = extract_nonce(&own_ke_key_arc_content.protected_headers)?;

    let (peer_pub_key, peer_identity, peer_nonce) =
        decode_peer_info(peer_key, peer_id, peer_nonce)?;

    let ecdh_secret = compute_shared_secret(
        &*imp.ecdh,
        &EcExchangeKeyPriv(take(&mut own_ke_key_arc_content.payload.0)),
        &peer_pub_key,
    )?;

    let (sign_key, own_identity) = imp.device.get_identity()?;
    let own_ke_pub_key = own_ke_key
        .pub_key
        .ok_or(ag_err!(InvalidPubKeyInKey, "own public key is missing for key agreement"))?;
    let own_ke_pub_key = EcExchangeKeyPub(
        CoseKey::from_slice(&own_ke_pub_key)
            .map_err(|e| ag_err!(InvalidKeKey, "invalid own key for key agreement: {:?}", e))?,
    );

    let salt_input = SaltInput {
        source_version: imp.device.get_source_version(),
        sink_ke_pub_key: peer_pub_key,
        source_ke_pub_key: own_ke_pub_key,
        sink_ke_nonce: peer_nonce.clone(),
        source_ke_nonce: own_ke_nonce.clone(),
        sink_cert_chain: peer_identity.cert_chain.clone(),
        source_cert_chain: own_identity.cert_chain.clone(),
    };

    let salt = compute_salt(salt_input, &*imp.sha256)?;

    let (in_encrypt_key, out_encrypt_key, hmac_key) =
        derive_shared_keys(&ecdh_secret, &salt, Role::Source, &*imp.hkdf)?;

    let (session_id, signature) = compute_sign_session_id(
        SessionIdInput { sink_ke_nonce: peer_nonce, source_ke_nonce: own_ke_nonce },
        HmacKey(hmac_key.0),
        sign_key,
        imp,
    )?;

    // Process/verify peer's cert chain and the peer's signature on the session id and retrieve the
    // peer's public signing key
    let verify_key = imp.device.process_peer_cert_chain(&peer_identity.cert_chain, &*imp.ecdsa)?;
    verify_signature_on_session_id(&verify_key, &session_id, peer_sig, &*imp.ecdsa)?;

    // create two arcs encrypting the two shared encrypting keys with the per-boot-key
    let shared_keys = create_shared_key_arcs(
        peer_identity,
        own_identity,
        AesKey(in_encrypt_key.0),
        AesKey(out_encrypt_key.0),
        &session_id,
        arc::AuthenticationCompleted(true),
        imp,
    )?;

    Ok(SessionInfo { shared_keys, session_id, session_id_signature: signature })
}

/// This is invoked on P2 (sink)
pub fn authentication_complete(
    imp: &mut TraitImpl,
    peer_sig: &[u8],
    shared_keys: [Vec<u8>; 2],
) -> Result<[Vec<u8>; 2], Error> {
    let in_key_arc = &shared_keys[0];
    let out_key_arc = &shared_keys[1];

    let pbk = imp.device.get_per_boot_key()?;

    let in_key_arc_content = arc::decipher_arc(&pbk, in_key_arc, &*imp.aes_gcm)?;
    let (in_session_id, in_source_identity) =
        process_shared_key_arc_headers(&in_key_arc_content.protected_headers)?;

    let out_key_arc_content = arc::decipher_arc(&pbk, out_key_arc, &*imp.aes_gcm)?;
    let (out_session_id, out_source_identity) =
        process_shared_key_arc_headers(&out_key_arc_content.protected_headers)?;

    if in_session_id != out_session_id {
        return Err(ag_err!(InvalidSharedKeyArcs, "session id mismatch"));
    }

    if in_source_identity != out_source_identity {
        return Err(ag_err!(InvalidSharedKeyArcs, "peer identity mismatch"));
    }

    let peer_identity = Identity::from_slice(&in_source_identity)?;

    // Process/verify peer's cert chain and the peer's signature on the session id
    let verify_key = imp.device.process_peer_cert_chain(&peer_identity.cert_chain, &*imp.ecdsa)?;
    verify_signature_on_session_id(&verify_key, &in_session_id, peer_sig, &*imp.ecdsa)?;

    let updated_shared_key_arcs =
        auth_complete_shared_key_arcs(in_key_arc_content, out_key_arc_content, imp)?;

    Ok(updated_shared_key_arcs)
}

fn decode_peer_info(
    pub_key: &[u8],
    identity: &[u8],
    nonce: &[u8],
) -> Result<(EcExchangeKeyPub, Identity, Nonce16), Error> {
    let pub_key = EcExchangeKeyPub(
        CoseKey::from_slice(pub_key)
            .map_err(|e| ag_err!(InvalidKeKey, "invalid peer key for key agreement: {:?}", e))?,
    );
    let identity = Identity::from_slice(identity)
        .map_err(|e| ag_err!(InvalidIdentity, "invalid peer identity: {:?}", e))?;
    let nonce = Nonce16(
        nonce.try_into().map_err(|e| ag_err!(InvalidPeerNonce, "invalid nonce size: {:?}", e))?,
    );
    Ok((pub_key, identity, nonce))
}

fn compute_shared_secret(
    ecdh: &dyn EcDh,
    own_key: &EcExchangeKeyPriv,
    peer_key: &EcExchangeKeyPub,
) -> Result<EcdhSecret, Error> {
    check_cose_key_params(
        &peer_key.0,
        iana::KeyType::EC2,
        iana::Algorithm::ECDH_ES_HKDF_256, // ECDH
        iana::EllipticCurve::P_256,
        ErrorCode::InvalidPeerKeKey,
    )?;
    ecdh.compute_shared_secret(own_key, peer_key)
}

fn compute_salt(salt_input: SaltInput, sha_256: &dyn Sha256) -> Result<[u8; 32], Error> {
    sha_256.compute_sha256(&salt_input.to_vec()?)
}

fn derive_shared_keys(
    ecdh_secret: &EcdhSecret,
    salt: &[u8; 32],
    role: Role,
    hkdf: &dyn Hkdf,
) -> Result<(PseudoRandKey, PseudoRandKey, PseudoRandKey), Error> {
    let pseudo_rand_key = hkdf.extract(salt, ecdh_secret)?;
    let hmac_key = hkdf.expand(&pseudo_rand_key, CONTEXT_KE_HMAC_KEY)?;
    match role {
        Role::Sink => {
            let in_encrypt_key = hkdf.expand(&pseudo_rand_key, CONTEXT_KE_ENCRYPTION_KEY_1)?;
            let out_encrypt_key = hkdf.expand(&pseudo_rand_key, CONTEXT_KE_ENCRYPTION_KEY_2)?;
            Ok((in_encrypt_key, out_encrypt_key, hmac_key))
        }
        Role::Source => {
            let in_encrypt_key = hkdf.expand(&pseudo_rand_key, CONTEXT_KE_ENCRYPTION_KEY_2)?;
            let out_encrypt_key = hkdf.expand(&pseudo_rand_key, CONTEXT_KE_ENCRYPTION_KEY_1)?;
            Ok((in_encrypt_key, out_encrypt_key, hmac_key))
        }
    }
}

fn compute_sign_session_id(
    session_id_input: SessionIdInput,
    hmac_key: HmacKey,
    sign_key: Option<EcSignKey>,
    imp: &mut TraitImpl,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let session_id = imp.hmac.compute_hmac(&hmac_key, &session_id_input.to_vec()?)?;

    // Construct `CoseSign1`
    let protected = HeaderBuilder::new().algorithm(imp.device.get_cose_sign_algorithm()).build();
    let cose_sign1 = CoseSign1Builder::new()
        .protected(protected)
        .try_create_detached_signature(&session_id, &[], |input| match sign_key {
            Some(key) => imp.ecdsa.sign(&key, input),
            None => imp.device.sign_data(&*imp.ecdsa, input),
        })?
        .build();

    Ok((session_id, cose_sign1.to_vec()?))
}

/// Verify the signature in a CBOR-encoded `COSE_Sign1` with detached payload `session_id`.
pub fn verify_signature_on_session_id(
    verify_key: &EcVerifyKey,
    session_id: &[u8],
    signature: &[u8],
    ecdsa: &dyn EcDsa,
) -> Result<(), Error> {
    let cose_sign1 = CoseSign1::from_slice(signature)?;
    match verify_key {
        EcVerifyKey::Ed25519(cose_key) => {
            check_cose_key_params(
                cose_key,
                iana::KeyType::OKP,
                iana::Algorithm::EdDSA,
                iana::EllipticCurve::Ed25519,
                ErrorCode::InvalidCertChain,
            )?;
        }
        EcVerifyKey::P256(cose_key) => {
            check_cose_key_params(
                cose_key,
                iana::KeyType::EC2,
                iana::Algorithm::ES256, // ECDSA
                iana::EllipticCurve::P_256,
                ErrorCode::InvalidCertChain,
            )?;
        }
        EcVerifyKey::P384(cose_key) => {
            check_cose_key_params(
                cose_key,
                iana::KeyType::EC2,
                iana::Algorithm::ES384,
                iana::EllipticCurve::P_384,
                ErrorCode::InvalidCertChain,
            )?;
        }
    }
    cose_sign1.verify_detached_signature(session_id, &[], |signature, data| {
        ecdsa.verify_signature(verify_key, data, signature)
    })
}

fn create_shared_key_arcs(
    sink_id: Identity,
    source_id: Identity,
    in_encrypt_key: AesKey,
    out_encrypt_key: AesKey,
    session_id: &[u8],
    auth_complete: arc::AuthenticationCompleted,
    imp: &mut TraitImpl,
) -> Result<[Vec<u8>; 2], Error> {
    let pbk = match auth_complete.0 {
        false => imp.device.get_or_create_per_boot_key(&*imp.aes_gcm, &mut *imp.rng)?,
        true => imp.device.get_per_boot_key()?,
    };

    // auth complete protected header
    let auth_complete_hdr = (arc::AUTHENTICATION_COMPLETE, Value::Bool(auth_complete.0));
    // session id protected header
    let session_id_hdr = (arc::SESSION_ID, Value::Bytes(try_to_vec(session_id)?));
    // direction of encryption
    let in_direction_hdr =
        (arc::DIRECTION, Value::Integer((arc::DirectionOfEncryption::In as i32).into()));
    // permissions header
    let permissions_encoded = arc::Permissions {
        source_id: Some(source_id),
        sink_id: Some(sink_id),
        ..Default::default()
    }
    .to_cbor_value()?;
    let permission_hdr = (arc::PERMISSIONS, permissions_encoded);

    let mut in_protected_headers = Vec::<(Label, Value)>::new();
    in_protected_headers.try_reserve(4)?;
    in_protected_headers.push(auth_complete_hdr.clone());
    in_protected_headers.push(session_id_hdr.clone());
    in_protected_headers.push(permission_hdr.clone());
    in_protected_headers.push(in_direction_hdr);

    let in_encrypt_key_arc = arc::create_arc(
        &pbk,
        arc::ArcContent {
            payload: ArcPayload(in_encrypt_key.0.to_vec()),
            protected_headers: in_protected_headers,
            ..Default::default()
        },
        &*imp.aes_gcm,
        &mut *imp.rng,
    )?;

    // direction of encryption
    let out_direction_hdr =
        (arc::DIRECTION, Value::Integer((arc::DirectionOfEncryption::Out as i32).into()));
    let mut out_protected_headers = Vec::<(Label, Value)>::new();
    out_protected_headers.try_reserve(4)?;
    out_protected_headers.push(auth_complete_hdr);
    out_protected_headers.push(session_id_hdr);
    out_protected_headers.push(permission_hdr);
    out_protected_headers.push(out_direction_hdr);

    let out_encrypt_key_arc = arc::create_arc(
        &pbk,
        arc::ArcContent {
            payload: ArcPayload(out_encrypt_key.0.to_vec()),
            protected_headers: out_protected_headers,
            ..Default::default()
        },
        &*imp.aes_gcm,
        &mut *imp.rng,
    )?;
    Ok([in_encrypt_key_arc, out_encrypt_key_arc])
}

/// Process the given protected headers of an arc and return the nonce used for key agreement
pub fn extract_nonce(protected_headers: &[(Label, Value)]) -> Result<Nonce16, Error> {
    for (label, val) in protected_headers {
        if *label == arc::KE_NONCE {
            match val {
                Value::Bytes(ref b) => {
                    return Ok(Nonce16(b.clone().try_into().map_err(|e| {
                        ag_err!(
                            InvalidPrivKeyArcInKey,
                            "invalid length of own nonce for key agreement: {:?}",
                            e
                        )
                    })?))
                }
                _ => {
                    return Err(ag_err!(
                        InvalidPubKeyInKey,
                        "invalid encoding of own nonce for key agreement"
                    ))
                }
            };
        }
    }

    Err(ag_err!(InvalidPrivKeyArcInKey, "nonce for key agreement is missing in the headers"))
}

/// Return the session id and the source identity for verifications done in
/// `authentication_complete`.
pub fn process_shared_key_arc_headers(
    protected_headers: &[(Label, Value)],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut session_id = None;
    let mut permissions = None;

    for (label, val) in protected_headers {
        if *label == arc::SESSION_ID {
            match val {
                Value::Bytes(ref b) => session_id = Some(b).cloned(),
                _ => return Err(ag_err!(InvalidSharedKeyArcs, "invalid encoding of session id")),
            }
        }
        if *label == arc::PERMISSIONS {
            permissions = Some(arc::Permissions::from_cbor_value(val.clone())?);
        }
    }
    Ok((
        session_id.ok_or(ag_err!(InvalidSharedKeyArcs, "session id is missing"))?,
        permissions
            .ok_or(ag_err!(InvalidSharedKeyArcs, "permissions are missing"))?
            .source_id
            .ok_or(ag_err!(InvalidSharedKeyArcs, "source identity is missing in the permissions"))?
            .to_vec()?,
    ))
}

/// Update the `authentication_complete` protected header in both arcs to be true
pub fn auth_complete_shared_key_arcs(
    mut in_arc_content: arc::ArcContent,
    mut out_arc_content: arc::ArcContent,
    imp: &mut TraitImpl,
) -> Result<[Vec<u8>; 2], Error> {
    in_arc_content.protected_headers.retain(|v| v.0 != arc::AUTHENTICATION_COMPLETE);
    out_arc_content.protected_headers.retain(|v| v.0 != arc::AUTHENTICATION_COMPLETE);

    let auth_complete_hdr = (arc::AUTHENTICATION_COMPLETE, Value::Bool(true));
    in_arc_content.protected_headers.try_push(auth_complete_hdr.clone())?;
    out_arc_content.protected_headers.try_push(auth_complete_hdr)?;

    let pbk = imp.device.get_per_boot_key()?;
    let in_encrypt_key_arc = arc::create_arc(&pbk, in_arc_content, &*imp.aes_gcm, &mut *imp.rng)?;
    let out_encrypt_key_arc = arc::create_arc(&pbk, out_arc_content, &*imp.aes_gcm, &mut *imp.rng)?;
    Ok([in_encrypt_key_arc, out_encrypt_key_arc])
}
