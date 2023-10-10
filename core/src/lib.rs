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

//! Core Authgraph operations

#![no_std]
extern crate alloc;
use alloc::vec::Vec;

pub mod error;
pub mod key;
pub mod traits;

/// Extension trait to provide fallible-allocation variants of `Vec` methods.
pub trait FallibleAllocExt<T> {
    /// Try to add the `value` to the collection, failing on memory exhaustion.
    fn try_push(&mut self, value: T) -> Result<(), alloc::collections::TryReserveError>;
    /// Try to extend the collection with the contents of `other`, failing on memory exhaustion.
    fn try_extend_from_slice(
        &mut self,
        other: &[T],
    ) -> Result<(), alloc::collections::TryReserveError>
    where
        T: Clone;
}

impl<T> FallibleAllocExt<T> for Vec<T> {
    fn try_push(&mut self, value: T) -> Result<(), alloc::collections::TryReserveError> {
        self.try_reserve(1)?;
        self.push(value);
        Ok(())
    }
    fn try_extend_from_slice(
        &mut self,
        other: &[T],
    ) -> Result<(), alloc::collections::TryReserveError>
    where
        T: Clone,
    {
        self.try_reserve(other.len())?;
        self.extend_from_slice(other);
        Ok(())
    }
}
