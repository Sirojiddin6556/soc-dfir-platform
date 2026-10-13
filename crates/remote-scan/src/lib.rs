#![forbid(unsafe_code)]
//! Credentialed remote-host vulnerability scanner.
//!
//! The platform runs this from the operator's own machine against a host they
//! enter, connecting over SSH and issuing only read-only commands. The host's
//! OS, kernel and installed-package inventory are collected remotely and then
//! matched against the same OSV advisory database the local Linux scan uses, so
//! a remote finding is as true as a local one — there is no second, looser
//! matcher.
//!
//! Safety is structural, not merely careful:
//! - Every command the scanner can issue is a variant of [`command::ReadCommand`];
//!   there is no way to pass an arbitrary string, so the scanner can only read.
//! - The SSH transport confirms the server's host key before any password or
//!   key is offered (trust on first use with explicit fingerprint
//!   confirmation), so credentials are never sent to an unverified host.
//! - Credentials live only for the duration of a scan and are never serialised
//!   into a report or a log.
//!
//! The collection pipeline ([`inventory`], [`scan`]) is transport-agnostic: it
//! drives a [`command::CommandRunner`], which the SSH transport implements and
//! which tests drive with captured command output. This keeps the whole
//! matching path unit-testable with no network.

pub mod command;
pub mod inventory;
pub mod scan;
pub mod types;

#[cfg(feature = "ssh")]
pub mod ssh;

pub use scan::scan_remote;
pub use types::{
    Credential, HostKey, HostKeyPolicy, RemoteError, RemoteInventory, RemoteScanReport,
    RemoteScanStatus, RemoteTarget,
};
