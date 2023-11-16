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

//! Tests for BoringSSL-based implementations of AuthGraph traits.

use authgraph_core::traits;
use authgraph_core_test as ag_test;

#[test]
fn test_rng() {
    let mut rng = crate::BoringRng;
    ag_test::test_rng(&mut rng);
}

#[test]
fn test_sha256() {
    ag_test::test_sha256(&crate::BoringSha256);
}

#[test]
fn test_hmac() {
    ag_test::test_hmac(&crate::BoringHmac);
}

#[test]
fn test_hkdf() {
    ag_test::test_hkdf(&crate::BoringHkdf);
}

#[test]
fn test_aes_gcm_keygen() {
    ag_test::test_aes_gcm_keygen(&crate::BoringAes, &mut crate::BoringRng);
}

#[test]
fn test_aes_gcm_roundtrip() {
    ag_test::test_aes_gcm_roundtrip(&crate::BoringAes, &mut crate::BoringRng);
}

#[test]
fn test_aes_gcm() {
    ag_test::test_aes_gcm(&crate::BoringAes);
}

#[test]
fn test_ecdh() {
    ag_test::test_ecdh(&crate::BoringEcDh);
}

#[test]
fn test_ecdsa() {
    ag_test::test_ecdsa(&crate::BoringEcDsa);
}

#[test]
fn test_ed25519_round_trip() {
    ag_test::test_ed25519_round_trip(&crate::BoringEcDsa);
}

#[test]
fn test_p256_round_trip() {
    ag_test::test_p256_round_trip(&crate::BoringEcDsa);
}

#[test]
fn test_p384_round_trip() {
    ag_test::test_p384_round_trip(&crate::BoringEcDsa);
}

#[test]
fn test_key_exchange_protocol() {
    let mut p1_imp = traits::TraitImpl {
        aes_gcm: Box::new(crate::BoringAes),
        ecdh: Box::new(crate::BoringEcDh),
        ecdsa: Box::new(crate::BoringEcDsa),
        hmac: Box::new(crate::BoringHmac),
        hkdf: Box::new(crate::BoringHkdf),
        sha256: Box::new(crate::BoringSha256),
        rng: Box::new(crate::BoringRng),
        device: Box::<crate::test_device::AgDevice>::default(),
        clock: None,
    };
    let mut p2_imp = traits::TraitImpl {
        aes_gcm: Box::new(crate::BoringAes),
        ecdh: Box::new(crate::BoringEcDh),
        ecdsa: Box::new(crate::BoringEcDsa),
        hmac: Box::new(crate::BoringHmac),
        hkdf: Box::new(crate::BoringHkdf),
        sha256: Box::new(crate::BoringSha256),
        rng: Box::new(crate::BoringRng),
        device: Box::<crate::test_device::AgDevice>::default(),
        clock: None,
    };
    ag_test::test_key_exchange_create(&mut p1_imp);
    ag_test::test_key_exchange_init(&mut p1_imp, &mut p2_imp);
    ag_test::test_key_exchange_finish(&mut p1_imp, &mut p2_imp);
    ag_test::test_key_exchange_auth_complete(&mut p1_imp, &mut p2_imp);
}

#[test]
fn test_ke_with_newer_source() {
    let source_device = crate::test_device::AgDevice::default();
    source_device.set_version(2);

    let sink_device = crate::test_device::AgDevice::default();
    sink_device.set_version(1);

    let mut p1_imp = traits::TraitImpl {
        aes_gcm: Box::new(crate::BoringAes),
        ecdh: Box::new(crate::BoringEcDh),
        ecdsa: Box::new(crate::BoringEcDsa),
        hmac: Box::new(crate::BoringHmac),
        hkdf: Box::new(crate::BoringHkdf),
        sha256: Box::new(crate::BoringSha256),
        rng: Box::new(crate::BoringRng),
        device: Box::new(source_device),
        clock: None,
    };

    let mut p2_imp = traits::TraitImpl {
        aes_gcm: Box::new(crate::BoringAes),
        ecdh: Box::new(crate::BoringEcDh),
        ecdsa: Box::new(crate::BoringEcDsa),
        hmac: Box::new(crate::BoringHmac),
        hkdf: Box::new(crate::BoringHkdf),
        sha256: Box::new(crate::BoringSha256),
        rng: Box::new(crate::BoringRng),
        device: Box::new(sink_device),
        clock: None,
    };

    ag_test::test_ke_with_newer_source(&mut p1_imp, &mut p2_imp);
}

#[test]
fn test_ke_with_newer_sink() {
    let source_device = crate::test_device::AgDevice::default();
    source_device.set_version(1);

    let sink_device = crate::test_device::AgDevice::default();
    sink_device.set_version(2);

    let mut p1_imp = traits::TraitImpl {
        aes_gcm: Box::new(crate::BoringAes),
        ecdh: Box::new(crate::BoringEcDh),
        ecdsa: Box::new(crate::BoringEcDsa),
        hmac: Box::new(crate::BoringHmac),
        hkdf: Box::new(crate::BoringHkdf),
        sha256: Box::new(crate::BoringSha256),
        rng: Box::new(crate::BoringRng),
        device: Box::new(source_device),
        clock: None,
    };
    let mut p2_imp = traits::TraitImpl {
        aes_gcm: Box::new(crate::BoringAes),
        ecdh: Box::new(crate::BoringEcDh),
        ecdsa: Box::new(crate::BoringEcDsa),
        hmac: Box::new(crate::BoringHmac),
        hkdf: Box::new(crate::BoringHkdf),
        sha256: Box::new(crate::BoringSha256),
        rng: Box::new(crate::BoringRng),
        device: Box::new(sink_device),
        clock: None,
    };
    ag_test::test_ke_with_newer_sink(&mut p1_imp, &mut p2_imp);
}

#[test]
fn test_ke_for_protocol_downgrade() {
    let source_device = crate::test_device::AgDevice::default();
    source_device.set_version(2);

    let sink_device = crate::test_device::AgDevice::default();
    sink_device.set_version(2);

    let mut p1_imp = traits::TraitImpl {
        aes_gcm: Box::new(crate::BoringAes),
        ecdh: Box::new(crate::BoringEcDh),
        ecdsa: Box::new(crate::BoringEcDsa),
        hmac: Box::new(crate::BoringHmac),
        hkdf: Box::new(crate::BoringHkdf),
        sha256: Box::new(crate::BoringSha256),
        rng: Box::new(crate::BoringRng),
        device: Box::new(source_device),
        clock: None,
    };
    let mut p2_imp = traits::TraitImpl {
        aes_gcm: Box::new(crate::BoringAes),
        ecdh: Box::new(crate::BoringEcDh),
        ecdsa: Box::new(crate::BoringEcDsa),
        hmac: Box::new(crate::BoringHmac),
        hkdf: Box::new(crate::BoringHkdf),
        sha256: Box::new(crate::BoringSha256),
        rng: Box::new(crate::BoringRng),
        device: Box::new(sink_device),
        clock: None,
    };
    ag_test::test_ke_for_version_downgrade(&mut p1_imp, &mut p2_imp);
}
