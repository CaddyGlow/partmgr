//! Internal standard-library and allocation-only portability boundary.
pub(crate) use crate::io;

#[cfg(not(feature = "std"))]
pub(crate) use alloc::string;
#[cfg(not(feature = "std"))]
pub(crate) use core::{array, cmp, error, fmt, iter, mem, ops, ptr, result, slice, str};
#[cfg(feature = "std")]
#[allow(unused_imports)] // Host test adapters use the same portability imports.
pub(crate) use std::{
    array, cell, cmp, env, error, ffi, fmt, fs, iter, mem, ops, os, panic, path, process, ptr,
    result, slice, str, string, thread,
};

#[cfg(not(feature = "std"))]
pub(crate) mod prelude {
    pub(crate) use alloc::{
        boxed::Box,
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
}
#[cfg(feature = "std")]
pub(crate) use std::{collections, sync};
#[cfg(not(feature = "std"))]
pub(crate) mod collections {
    pub(crate) use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
    pub(crate) use hashbrown::{HashMap, HashSet};
    pub(crate) mod btree_map {
        pub(crate) use alloc::collections::btree_map::*;
    }
}
#[cfg(not(feature = "std"))]
pub(crate) mod sync {
    pub(crate) use alloc::sync::Arc;
    pub(crate) use core::sync::atomic;

    /// Non-poisoning lock for short internal cache critical sections.
    /// Firmware callers must not reenter these sections from interrupt handlers.
    #[derive(Debug)]
    pub(crate) struct Mutex<T>(spin::Mutex<T>);
    #[derive(Debug)]
    pub(crate) struct LockError;
    impl core::fmt::Display for LockError {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("internal lock failure")
        }
    }
    impl core::error::Error for LockError {}
    impl<T> Mutex<T> {
        pub(crate) const fn new(value: T) -> Self {
            Self(spin::Mutex::new(value))
        }
        pub(crate) fn lock(&self) -> Result<spin::MutexGuard<'_, T>, LockError> {
            Ok(self.0.lock())
        }
    }
}
