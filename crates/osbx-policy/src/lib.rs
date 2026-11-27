//! Network policy for osbx sandboxes: rule model, presets and evaluation.
//!
//! Semantics follow the public Docker Sandboxes documentation:
//! * deny by default (except the `allow-all` preset);
//! * a deny rule from any source overrides any allow rule;
//! * kit rules apply under every preset, including `deny-all`;
//! * with organization governance active, only organization allow rules grant access
//!   (local, kit and preset allows are ignored; local denies still apply);
//! * unmatched requests under `balanced` / `deny-all` need interactive approval.
//!
//! Anything the docs do not specify is marked `ASSUMPTION:` in the docs of the item.

mod baseline;
mod dest;
mod engine;
mod rule;

pub use baseline::balanced_baseline;
pub use dest::{Destination, HostSpec, ParseError};
pub use engine::{Decision, Governance, PolicySet, Preset, Reason};
pub use rule::{Action, HttpMatch, HttpRequest, Origin, Request, Rule};
