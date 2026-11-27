//! Kit v3: descriptor model, strict decoding, validation, arg expansion and set resolution.
//!
//! Behavior follows the Apache-2.0 Kit specification (`docker/sandbox-kit-spec`,
//! `docs/spec/SPEC-v3.md`). Where the spec delegates to the Go reference
//! implementation, differences are recorded as `ASSUMPTION:`.
//!
//! Not yet implemented: OCI pull/push and the `docker/sandbox-kit:3` BuildKit frontend
//! (reuse upstream's Go frontend for builds), publishing-time derivations (§9.5-§9.7),
//! typed config checks for the remaining well-known capability types.

pub mod descriptor;
pub mod expand;
pub mod resolve;
pub mod validate;
pub mod version;

pub use descriptor::{Arg, Capability, CapabilityItem, Descriptor, Kind, KitRef};
pub use resolve::{KitInput, ResolveError, Selection, resolve, select};
/// Capability configs are carried as YAML values.
pub use serde_yaml_ng::Value as ConfigValue;
pub use validate::{Issue, validate, validate_published};
pub use version::{Provide, Requirement, Version};
