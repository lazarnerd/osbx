//! Host-side credential handling for osbx sandboxes.
//!
//! The sandbox only ever sees the placeholder [`SENTINEL`]; the proxy replaces it with
//! the real value on outbound requests (see [`inject`]). Real values live in a
//! [`SecretStore`] on the host, optionally resolved at use time from a command or a
//! vault reference ([`Source`]) and cached for [`DEFAULT_TTL`].
//!
//! Implemented stores: [`MemoryStore`] and [`FileStore`] (0700 directory, 0600 file,
//! the documented headless-Linux fallback). OS keychain backends (macOS Keychain,
//! Windows Credential Manager, Secret Service) are not implemented yet.

mod binding;
mod inject;
mod resolver;
mod services;
mod store;

pub use binding::{Bindings, Mechanism};
pub use inject::{InjectRule, inject};
pub use resolver::{Clock, CommandRunner, ResolveError, Resolver, ShellRunner, SystemClock};
pub use services::{Service, builtin_services, find_service};
pub use store::{FileStore, MemoryStore, Refresh, Scope, SecretStore, Source, StoreError, Stored};

/// Placeholder value the sandbox sees instead of a real credential.
pub const SENTINEL: &str = "proxy-managed";
/// Default re-resolution interval for command/ref sources (documented as 55 minutes).
pub const DEFAULT_TTL: std::time::Duration = std::time::Duration::from_secs(55 * 60);
