//! Descriptor types with strict decoding (spec §1.2, §4, §6, §7).

use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use std::collections::BTreeMap;

/// Kit kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Root filesystem plus launch config. Exactly one per composition.
    Workload,
    /// Overlay on a workload.
    Mixin,
    /// Authoring-only list of other kits.
    Set,
    /// Pre-rename spelling of `workload`; accepted on read, never to be authored.
    Sandbox,
}

/// One `args` entry.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Arg {
    /// Default value.
    pub default: Option<String>,
    /// Installer must supply a value.
    pub required: Option<bool>,
    /// Shown in input listings.
    pub description: Option<String>,
    /// Exact accepted values.
    #[serde(rename = "enum")]
    pub enum_values: Option<Vec<String>>,
    /// RE2 pattern for the whole value.
    pub pattern: Option<String>,
    /// Container env var name (create phase).
    pub env: Option<String>,
    /// Build arg name (build phase).
    pub build_arg: Option<String>,
    /// BuildKit secret id.
    pub build_secret: Option<String>,
}

/// One entry of a set's `kits:` list.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KitRef {
    /// Registry reference.
    #[serde(rename = "ref")]
    pub reference: String,
    /// `sha256:<64 hex>`.
    pub digest: Option<String>,
    /// Create-phase args of that kit.
    #[serde(default)]
    pub args: BTreeMap<String, String>,
}

/// A typed capability request.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capability {
    /// `<namespace>/<name>@<version>`.
    #[serde(rename = "type")]
    pub ty: String,
    /// Display label only.
    pub name: Option<String>,
    /// Skip instead of failing when the host cannot provide it. `None` = not stated
    /// (group members must not state it, even as `false`).
    pub optional: Option<bool>,
    /// Shown wherever the request is listed.
    pub description: Option<String>,
    /// Type-specific payload.
    pub config: Option<Value>,
    /// Diagnostic provenance (not a trust input).
    pub source: Option<Value>,
    /// Descriptor-local block ids.
    pub declaration_blocks: Option<Vec<String>>,
}

/// A group of capability requests selected atomically.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupBody {
    /// Display label.
    pub name: Option<String>,
    /// Whether the whole group may be skipped.
    #[serde(default)]
    pub optional: bool,
    /// Display description.
    pub description: Option<String>,
    /// Members (never nested groups).
    pub capabilities: Vec<Capability>,
}

/// A `capabilities:` item.
#[derive(Debug, Clone, PartialEq)]
pub enum CapabilityItem {
    /// Ordinary request.
    Request(Capability),
    /// Group of requests.
    Group(GroupBody),
}

impl CapabilityItem {
    fn from_value(v: Value) -> Result<Self, String> {
        let is_group = v.as_mapping().is_some_and(|m| m.contains_key("group"));
        if is_group {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct G {
                group: GroupBody,
            }
            let g: G = serde_yaml_ng::from_value(v).map_err(|e| e.to_string())?;
            Ok(Self::Group(g.group))
        } else {
            serde_yaml_ng::from_value(v)
                .map(Self::Request)
                .map_err(|e| e.to_string())
        }
    }
}

/// The Kit descriptor.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawDescriptor {
    schema_version: String,
    kind: Kind,
    display_name: Option<String>,
    author: Option<String>,
    description: Option<String>,
    source_url: Option<String>,
    icon_url: Option<String>,
    version: Option<String>,
    licenses: Option<Vec<String>>,
    #[serde(default)]
    provides: Vec<String>,
    provides_from: Option<BTreeMap<String, String>>,
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    integrates: Vec<String>,
    #[serde(default)]
    conflicts: Vec<String>,
    #[serde(default)]
    capabilities: Vec<Value>,
    #[serde(default)]
    args: BTreeMap<String, Arg>,
    build: Option<String>,
    dockerfile: Option<String>,
    #[serde(default)]
    kits: Vec<KitRef>,
}

/// A decoded Kit descriptor (not yet validated; see [`crate::validate`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Descriptor {
    /// Must be `"3"`.
    pub schema_version: String,
    /// Kit kind.
    pub kind: Kind,
    /// Display metadata.
    pub display_name: Option<String>,
    /// Display metadata (self-asserted).
    pub author: Option<String>,
    /// Display metadata.
    pub description: Option<String>,
    /// Display metadata.
    pub source_url: Option<String>,
    /// Display metadata, https only.
    pub icon_url: Option<String>,
    /// Fallback version.
    pub version: Option<String>,
    /// SPDX identifiers.
    pub licenses: Option<Vec<String>>,
    /// Offered kit-to-kit capabilities.
    pub provides: Vec<String>,
    /// Authored form only; workload only.
    pub provides_from: Option<BTreeMap<String, String>>,
    /// Must be satisfied by the resolved set.
    pub requires: Vec<String>,
    /// Applies only if a provider is present.
    pub integrates: Vec<String>,
    /// Must be absent from the resolved set.
    pub conflicts: Vec<String>,
    /// Host-answered requests.
    pub capabilities: Vec<CapabilityItem>,
    /// Installer-supplied values.
    pub args: BTreeMap<String, Arg>,
    /// Inline recipe.
    pub build: Option<String>,
    /// Companion recipe path.
    pub dockerfile: Option<String>,
    /// Set members.
    pub kits: Vec<KitRef>,
}

impl Capability {
    /// Whether the request may be skipped (`optional: true`).
    pub fn is_optional(&self) -> bool {
        self.optional.unwrap_or(false)
    }
}

impl Descriptor {
    /// Decode YAML (or the JSON of a published annotation) strictly: any unknown field
    /// anywhere is an error, and so is any NUL in any string (spec §1.2).
    pub fn from_yaml(src: &str) -> Result<Self, String> {
        let doc: Value = serde_yaml_ng::from_str(src).map_err(|e| e.to_string())?;
        if contains_nul(&doc) {
            return Err("descriptor contains NUL (U+0000) in a key or value".into());
        }
        let raw: RawDescriptor = serde_yaml_ng::from_value(doc).map_err(|e| e.to_string())?;
        let mut capabilities = Vec::with_capacity(raw.capabilities.len());
        for (i, v) in raw.capabilities.into_iter().enumerate() {
            capabilities.push(
                CapabilityItem::from_value(v).map_err(|e| format!("capabilities[{i}]: {e}"))?,
            );
        }
        Ok(Self {
            schema_version: raw.schema_version,
            kind: raw.kind,
            display_name: raw.display_name,
            author: raw.author,
            description: raw.description,
            source_url: raw.source_url,
            icon_url: raw.icon_url,
            version: raw.version,
            licenses: raw.licenses,
            provides: raw.provides,
            provides_from: raw.provides_from,
            requires: raw.requires,
            integrates: raw.integrates,
            conflicts: raw.conflicts,
            capabilities,
            args: raw.args,
            build: raw.build,
            dockerfile: raw.dockerfile,
            kits: raw.kits,
        })
    }

    /// Build a descriptor from an already-parsed YAML document (same checks as [`Self::from_yaml`]).
    pub fn from_value(doc: Value) -> Result<Self, String> {
        let text = serde_yaml_ng::to_string(&doc).map_err(|e| e.to_string())?;
        Self::from_yaml(&text)
    }

    /// Every capability request, flattening groups, with its block id (`None` = top level,
    /// `Some(i)` = the i-th group).
    pub fn requests(&self) -> impl Iterator<Item = (Option<usize>, &Capability)> {
        self.capabilities
            .iter()
            .enumerate()
            .flat_map(|(i, item)| match item {
                CapabilityItem::Request(c) => vec![(None, c)],
                CapabilityItem::Group(g) => g.capabilities.iter().map(|c| (Some(i), c)).collect(),
            })
    }
}

/// True if any string, key or value, anywhere in the document contains NUL (spec §1.2).
fn contains_nul(v: &Value) -> bool {
    match v {
        Value::String(s) => s.contains('\0'),
        Value::Sequence(s) => s.iter().any(contains_nul),
        Value::Mapping(m) => m.iter().any(|(k, x)| contains_nul(k) || contains_nul(x)),
        Value::Tagged(t) => contains_nul(&t.value),
        _ => false,
    }
}
