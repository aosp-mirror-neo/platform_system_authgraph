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

//! Error Handling

use alloc::string::String;
use coset::CoseError;

/// AuthGraph error codes from the AIDL definition.
#[derive(Debug)]
#[repr(i32)]
pub enum ErrorCode {
    /// Success
    Ok = 0,
    /// Invalid peer nonce for key agreement
    InvalidPeerNonce = -1,
    /// Invalid key agreement public key by the peer
    InvalidPeerKeKey = -2,
    /// Invalid identity of the peer
    InvalidIdentity = -3,
    /// Invalid certificate chain in the identity of the peer
    InvalidCertChain = -4,
    /// Invalid signature by the peer
    InvalidSignature = -5,
    /// Invalid key agreement key created by a particular party themselves to be used as a handle
    InvalidKeKey = -6,
    /// Invalid public key in the `Key` struct
    InvalidPubKeyInKey = -7,
    /// Invalid private key arc in the `Key` struct
    InvalidPrivKeyArcInKey = -8,
    /// Invalid shared key arcs
    InvalidSharedKeyArcs = -9,
    /// Memory allocation failed
    MemoryAllocationFailed = -10,
    /// Internal processing error
    InternalError = -11,
    /// Unimplemented
    Unimplemented = -12,
}

/// AuthGraph error type.
#[derive(Debug)]
pub struct Error(pub ErrorCode, pub String);

impl core::convert::From<CoseError> for Error {
    fn from(e: CoseError) -> Self {
        crate::ag_err!(InternalError, "CoseError: {}", e)
    }
}

impl From<alloc::collections::TryReserveError> for Error {
    fn from(e: alloc::collections::TryReserveError) -> Self {
        crate::ag_err!(MemoryAllocationFailed, "allocation of Vec failed: {:?}", e)
    }
}

/// Macro to build an [`Error`] instance.
/// E.g. use: `ag_err!(InternalError, "some {} format", arg)`.
#[macro_export]
macro_rules! ag_err {
    { $error_code:ident, $($arg:tt)+ } => {
        Error(ErrorCode::$error_code,
                        alloc::format!("{}:{}: {}", file!(), line!(), format_args!($($arg)+))) };
}
