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
