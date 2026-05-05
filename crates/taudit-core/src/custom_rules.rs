use crate::finding::{
    Finding, FindingCategory, FindingExtras, FindingSource, Recommendation, Severity,
};
use crate::graph::{AuthorityGraph, NodeKind, TrustZone};
use crate::propagation::PropagationPath;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MAX_INPUT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CUSTOM_RULE_VEC_ITEMS: usize = 1024;

/// Human-readable spelling of the `CustomRule.id` charset+length contract.
/// Reused in every validation error so operators always see the same regex.
const RULE_ID_REGEX: &str = "^[A-Za-z_][A-Za-z0-9_-]{0,63}$";

/// Charset + length contract for `CustomRule.id`. Snake_case + kebab-case
/// friendly, 64-char cap. Rejects empty, leading digits, brackets,
/// whitespace, and anything that would corrupt the `[id] name: …` finding
/// message contract or the SARIF/JSON `extract_custom_rule_id` heuristic.
fn validate_rule_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err(format!(
            "rule id must be non-empty (allowed: {RULE_ID_REGEX})"
        ));
    }
    if id.len() > 64 {
        return Err(format!(
            "rule id '{id}' exceeds 64 characters (allowed: {RULE_ID_REGEX})"
        ));
    }
    let mut chars = id.chars();
    let first = chars.next().expect("id non-empty checked above");
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(format!(
            "rule id '{id}' must start with an ASCII letter or underscore (allowed: {RULE_ID_REGEX})"
        ));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(format!(
                "rule id '{id}' contains invalid character '{c}' (allowed: ASCII letters, digits, underscore, hyphen — {RULE_ID_REGEX})"
            ));
        }
    }
    Ok(())
}

/// Serde shim: deserialise `CustomRule.id` as a `String`, then enforce the
/// validation contract above. The error is surfaced via
/// `serde::de::Error::custom` so it appears in `serde_yaml` parse errors with
/// a path/line annotation pointing at the offending document — operators see
/// exactly which YAML file's `id:` field is wrong.
fn deserialize_validated_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    validate_rule_id(&raw).map_err(de::Error::custom)?;
    Ok(raw)
}

fn deserialize_capped_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    if values.len() > MAX_CUSTOM_RULE_VEC_ITEMS {
        return Err(de::Error::custom(format!(
            "custom-rule list exceeds {MAX_CUSTOM_RULE_VEC_ITEMS} entries"
        )));
    }
    Ok(values)
}

/// A user-defined rule loaded from YAML. Fires when source, sink, and path
/// predicates all match a propagation path produced by the engine.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomRule {
    /// Stable identifier, embedded into every emitted finding's message and
    /// extracted by SARIF / JSON sinks via `extract_custom_rule_id`. Validated
    /// at deserialise time against `^[A-Za-z_][A-Za-z0-9_-]{0,63}$` so a
    /// malicious or sloppy YAML cannot inject `]`/`[`/whitespace and corrupt
    /// the message-encoding contract or empty out the rule attribution.
    #[serde(deserialize_with = "deserialize_validated_id")]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    pub category: FindingCategory,
    #[serde(rename = "match", default)]
    pub match_spec: MatchSpec,
    /// Path of the YAML file this rule was loaded from. Set by
    /// `load_rules_dir` / `parse_rules_multi_doc_with_source`. Threaded into
    /// every `Finding` this rule emits (`FindingSource::Custom`) so an
    /// operator inspecting JSON / SARIF output can distinguish authentic
    /// built-in findings from any rule that may have been planted in a
    /// shared `--invariants-dir`. Defaults to `None` for rules constructed
    /// in tests or in code paths that didn't go through the loader.
    #[serde(default, skip)]
    pub source_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MatchSpec {
    #[serde(default)]
    pub source: NodeMatcher,
    #[serde(default)]
    pub sink: NodeMatcher,
    #[serde(default)]
    pub path: PathMatcher,
    /// Graph-level metadata predicate. Applied to `AuthorityGraph::metadata`
    /// (e.g. `META_TRIGGER`, `META_REPOSITORIES`). When present, ALL conditions
    /// must hold *in addition to* source/sink/path. Reuses the same typed
    /// predicate language as node-level metadata (`equals`, `not_equals`,
    /// `contains`, `in`, plus `not:` negation).
    #[serde(default)]
    pub graph_metadata: MetadataMatcher,
    /// Standalone node predicate. When present, the matcher iterates every
    /// node in the graph and emits one finding per matching node — the
    /// source/sink/path fields are ignored, but `graph_metadata:` still
    /// applies as a graph-wide gate. This is the node-shape-only mode used
    /// for invariants like "any floating Image" where there is no
    /// propagation chain to walk.
    #[serde(default)]
    pub standalone: Option<NodeMatcher>,
}

/// Maximum number of elements allowed in a single `Vec<T>` deserialised
/// from a custom-rule YAML field. A hostile YAML with
/// `node_type: [secret, secret, … 10M times …]` would otherwise allocate
/// hundreds of MiB before any rule logic runs (multiple such fields per
/// rule, multiple rules per file = linear amplification). 1024 is well
/// above any realistic rule (the largest rule in the existing tree
/// names ~6 node kinds) and an obvious operator-actionable cap.
pub const MAX_RULE_VEC_LEN: usize = 1024;

/// A scalar-or-list helper. Lets YAML write `node_type: secret` (single value)
/// or `node_type: [secret, identity]` (any-of). Single form preserved for
/// backward compatibility with v0.4.x rule files.
///
/// The `Many` variant is capped at [`MAX_RULE_VEC_LEN`] elements at
/// deserialisation time — see the custom `Deserialize` impl below.
#[derive(Debug, Clone)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

// Custom Deserialize so we can enforce `MAX_RULE_VEC_LEN` *during* the
// sequence visit, before serde allocates a full Vec for an attacker.
//
// Behaviour matches the previous `#[serde(untagged)]` derive:
//   * a YAML scalar deserialises to `OneOrMany::One(t)`
//   * a YAML sequence deserialises to `OneOrMany::Many(vec)`
//   * any other shape errors via the standard serde error path
//
// A cap violation surfaces as a serde error referencing the field, so
// the resulting `serde_yaml::Error` already carries a path/line annotation
// pointing operators at the offending document.
impl<'de, T> Deserialize<'de> for OneOrMany<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OneOrManyVisitor<T> {
            _phantom: std::marker::PhantomData<T>,
        }

        impl<'de, T> Visitor<'de> for OneOrManyVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = OneOrMany<T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a single value or a sequence (max 1024 elements)")
            }

            // Forward every scalar shape to T's Deserialize via
            // `deserialize_any` on a tiny wrapper. We can't call T's
            // Deserialize directly here without a deserializer; instead
            // route through `IntoDeserializer` for the supported scalar
            // types serde_yaml emits.
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::BoolDeserializer::new(v)).map(OneOrMany::One)
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::I64Deserializer::new(v)).map(OneOrMany::One)
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::U64Deserializer::new(v)).map(OneOrMany::One)
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::F64Deserializer::new(v)).map(OneOrMany::One)
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::StrDeserializer::new(v)).map(OneOrMany::One)
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::StringDeserializer::new(v)).map(OneOrMany::One)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::UnitDeserializer::new()).map(OneOrMany::One)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                // Pre-size with a hint capped at MAX_RULE_VEC_LEN so a
                // hostile size_hint (e.g. usize::MAX) cannot trick us into
                // a giant up-front allocation either.
                let cap_hint = seq
                    .size_hint()
                    .map(|h| h.min(MAX_RULE_VEC_LEN))
                    .unwrap_or(0);
                let mut out: Vec<T> = Vec::with_capacity(cap_hint);
                while let Some(item) = seq.next_element::<T>()? {
                    if out.len() >= MAX_RULE_VEC_LEN {
                        return Err(de::Error::custom(format!(
                            "list field exceeds maximum of {MAX_RULE_VEC_LEN} elements; \
                             split into multiple rules instead"
                        )));
                    }
                    out.push(item);
                }
                Ok(OneOrMany::Many(out))
            }
        }

        deserializer.deserialize_any(OneOrManyVisitor::<T> {
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<T: PartialEq> OneOrMany<T> {
    fn contains(&self, value: &T) -> bool {
        match self {
            OneOrMany::One(v) => v == value,
            OneOrMany::Many(vs) => vs.iter().any(|v| v == value),
        }
    }
}

/// Per-field metadata predicate. Bare string is `equals` (back-compat with
/// v0.4.x). Operator object supports `equals`, `not_equals`, `contains` (substring
/// match on string values), and `in` (any-of allowed values).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum MetadataPredicate {
    /// `key: "value"` — equality (back-compat).
    Equals(String),
    /// `key: { equals/not_equals/contains/in: ... }`
    Op(MetadataOp),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataOp {
    #[serde(default)]
    pub equals: Option<String>,
    #[serde(default)]
    pub not_equals: Option<String>,
    /// Substring match on the string-valued metadata field.
    #[serde(default)]
    pub contains: Option<String>,
    /// Any-of allowed values. Capped at [`MAX_RULE_VEC_LEN`] elements at
    /// deserialise time so a hostile YAML cannot allocate an unbounded
    /// `Vec<String>` before any rule logic runs.
    #[serde(
        default,
        rename = "in",
        deserialize_with = "deserialize_capped_opt_vec_string"
    )]
    pub in_: Option<Vec<String>>,
}

/// Deserialize `Option<Vec<String>>` while enforcing
/// [`MAX_RULE_VEC_LEN`] inside the sequence visitor. The error message
/// names the cap and recommends splitting the rule, matching the
/// `OneOrMany` cap diagnostic so operators see consistent guidance.
fn deserialize_capped_opt_vec_string<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct CappedVecStringVisitor;

    impl<'de> Visitor<'de> for CappedVecStringVisitor {
        type Value = Option<Vec<String>>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a sequence of strings (max 1024 elements) or null")
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_seq(self)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let cap_hint = seq
                .size_hint()
                .map(|h| h.min(MAX_RULE_VEC_LEN))
                .unwrap_or(0);
            let mut out: Vec<String> = Vec::with_capacity(cap_hint);
            while let Some(item) = seq.next_element::<String>()? {
                if out.len() >= MAX_RULE_VEC_LEN {
                    return Err(de::Error::custom(format!(
                        "metadata `in:` list exceeds maximum of {MAX_RULE_VEC_LEN} \
                         elements; split into multiple rules instead"
                    )));
                }
                out.push(item);
            }
            Ok(Some(out))
        }
    }

    deserializer.deserialize_option(CappedVecStringVisitor)
}

impl MetadataOp {
    fn matches(&self, actual: Option<&String>) -> bool {
        // If the metadata key is absent, only `not_equals` can succeed (against
        // anything-not-this-value), all positive operators fail.
        if let Some(want) = &self.equals {
            if actual.map(|s| s.as_str()) != Some(want.as_str()) {
                return false;
            }
        }
        if let Some(want) = &self.not_equals {
            if actual.map(|s| s.as_str()) == Some(want.as_str()) {
                return false;
            }
        }
        if let Some(needle) = &self.contains {
            match actual {
                Some(s) if s.contains(needle.as_str()) => {}
                _ => return false,
            }
        }
        if let Some(allowed) = &self.in_ {
            match actual {
                Some(s) if allowed.iter().any(|a| a == s) => {}
                _ => return false,
            }
        }
        true
    }
}

impl MetadataPredicate {
    fn matches(&self, actual: Option<&String>) -> bool {
        match self {
            MetadataPredicate::Equals(want) => actual.map(|s| s.as_str()) == Some(want.as_str()),
            MetadataPredicate::Op(op) => op.matches(actual),
        }
    }
}

/// Metadata matcher: map of field -> predicate, with an optional `not`
/// sub-matcher (negation). The `not:` key is reserved and parsed specially —
/// it cannot be used as a metadata field name.
#[derive(Debug, Clone, Default)]
pub struct MetadataMatcher {
    pub fields: HashMap<String, MetadataPredicate>,
    pub not: Option<Box<MetadataMatcher>>,
}

impl MetadataMatcher {
    fn matches(&self, metadata: &HashMap<String, String>) -> bool {
        for (key, pred) in &self.fields {
            if !pred.matches(metadata.get(key)) {
                return false;
            }
        }
        if let Some(inner) = &self.not {
            if inner.matches(metadata) {
                return false;
            }
        }
        true
    }

    fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.not.is_none()
    }
}

// Custom Deserialize: pull out reserved `not` key, rest become field predicates.
impl<'de> Deserialize<'de> for MetadataMatcher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MetadataMatcherVisitor;

        impl<'de> Visitor<'de> for MetadataMatcherVisitor {
            type Value = MetadataMatcher;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a metadata predicate map (field -> string|operator) with optional `not:` sub-map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<MetadataMatcher, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut fields: HashMap<String, MetadataPredicate> = HashMap::new();
                let mut not: Option<Box<MetadataMatcher>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    if key == "not" {
                        if not.is_some() {
                            return Err(de::Error::duplicate_field("not"));
                        }
                        let inner: MetadataMatcher = map.next_value()?;
                        not = Some(Box::new(inner));
                    } else {
                        let value: MetadataPredicate = map.next_value()?;
                        if fields.insert(key.clone(), value).is_some() {
                            return Err(de::Error::custom(format!(
                                "duplicate metadata field `{key}`"
                            )));
                        }
                    }
                }

                Ok(MetadataMatcher { fields, not })
            }
        }

        deserializer.deserialize_map(MetadataMatcherVisitor)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NodeMatcher {
    /// Single value (`node_type: secret`) or any-of list (`[secret, identity]`).
    #[serde(default)]
    pub node_type: Option<OneOrMany<NodeKind>>,
    /// Single value or any-of list.
    #[serde(default)]
    pub trust_zone: Option<OneOrMany<TrustZone>>,
    #[serde(default)]
    pub metadata: MetadataMatcher,
    /// Negation: matches when the inner sub-matcher does NOT match.
    /// Nested `not` is allowed and double-negation collapses naturally.
    #[serde(default)]
    pub not: Option<Box<NodeMatcher>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PathMatcher {
    #[serde(default, deserialize_with = "deserialize_capped_vec")]
    pub crosses_to: Vec<TrustZone>,
}

#[derive(Debug)]
pub enum CustomRuleError {
    FileRead(PathBuf, io::Error),
    YamlParse(PathBuf, serde_yaml::Error),
    FileTooLarge {
        path: PathBuf,
        max_bytes: u64,
        actual_bytes: u64,
    },
    /// A symlink in the rules directory resolved to a path outside the
    /// declared `--invariants-dir` tree. Refused unless the caller opts in
    /// via `allow_external_symlinks: true` (CLI flag
    /// `--invariants-allow-external-symlinks`). See red-team R2 #4.
    SymlinkOutsideDir {
        link: PathBuf,
        target: PathBuf,
    },
}

impl fmt::Display for CustomRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustomRuleError::FileRead(path, err) => {
                write!(
                    f,
                    "failed to read custom rule file {}: {err}",
                    path.display()
                )
            }
            CustomRuleError::YamlParse(path, err) => {
                write!(
                    f,
                    "failed to parse custom rule file {}: {err}",
                    path.display()
                )
            }
            CustomRuleError::FileTooLarge {
                path,
                max_bytes,
                actual_bytes,
            } => {
                write!(
                    f,
                    "custom rule file {} exceeds {max_bytes} byte limit ({actual_bytes} bytes)",
                    path.display()
                )
            }
            CustomRuleError::SymlinkOutsideDir { link, target } => {
                write!(
                    f,
                    "refusing to follow symlink {} → {} (target outside --invariants-dir; potential symlink traversal). Use --invariants-allow-external-symlinks to override.",
                    link.display(),
                    target.display()
                )
            }
        }
    }
}

impl std::error::Error for CustomRuleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CustomRuleError::FileRead(_, err) => Some(err),
            CustomRuleError::YamlParse(_, err) => Some(err),
            CustomRuleError::FileTooLarge { .. } => None,
            CustomRuleError::SymlinkOutsideDir { .. } => None,
        }
    }
}

/// Load all `*.yml` and `*.yaml` files from `dir`. Files are read in sorted
/// order for deterministic output. Returns a list of all errors alongside
/// successfully parsed rules — callers decide whether to fail fast or continue.
///
/// Symlinks pointing OUTSIDE `dir` are refused by default (red-team R2 #4).
/// Use [`load_rules_dir_with_opts`] to opt into the legacy follow-everything
/// behavior.
pub fn load_rules_dir(dir: &Path) -> Result<Vec<CustomRule>, Vec<CustomRuleError>> {
    load_rules_dir_with_opts(dir, false)
}

/// Like [`load_rules_dir`] but lets the caller decide what to do with
/// symlinks that escape the declared directory.
///
/// - The loader walks `dir` **recursively** via a hand-rolled DFS, so
///   operators can organise rules into subdirectories like
///   `invariants/gha/`, `invariants/ado/` and have all of them load.
/// - In-tree symlinks (canonicalized target lives under canonicalized `dir`)
///   are always followed; a stderr warning is emitted naming the link and
///   target so the user is never surprised.
/// - Out-of-tree symlinks are:
///   - REFUSED with a `CustomRuleError::SymlinkOutsideDir` when
///     `allow_external_symlinks` is `false` (default — safe).
///   - Followed, with a louder stderr warning, when
///     `allow_external_symlinks` is `true` (caller opted in via
///     `--invariants-allow-external-symlinks`).
/// - Files reached via multiple paths (e.g. `real.yml` and an `alias.yml ->
///   ./real.yml` symlink in the same tree) are deduplicated by canonical
///   path so the same rule never fires twice. A stderr warning is emitted
///   when a duplicate is dropped.
///
/// Why: the loader walks `--invariants-dir` recursively and previously
/// followed every symlink without checking. A symlink under the directory
/// pointing OUT (e.g. to `/etc/passwd` or an attacker-controlled file)
/// was silently read in. This function makes that escape opt-in.
pub fn load_rules_dir_with_opts(
    dir: &Path,
    allow_external_symlinks: bool,
) -> Result<Vec<CustomRule>, Vec<CustomRuleError>> {
    // Canonicalize the directory once so we can compare every symlink target
    // against the same normalized prefix. If canonicalization fails (e.g. a
    // broken symlink in the path), fall back to the literal path — better to
    // be conservative and treat *every* symlink as out-of-tree than to crash.
    let canonical_dir = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());

    let mut errors: Vec<CustomRuleError> = Vec::new();
    // Pairs of (literal_path, canonical_path) for YAML files to read.
    // Literal path is stamped into `FindingSource::Custom.source_file` so
    // operator-facing output retains the path as written; canonical path
    // is the dedup key so symlink aliases collapse to a single rule load.
    let mut files: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    // Visited directory canonical paths — guards against cycles introduced
    // by directory symlinks looping back into an ancestor.
    let mut visited_dirs: HashSet<PathBuf> = HashSet::new();
    visited_dirs.insert(canonical_dir.clone());

    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];

    while let Some(current) = stack.pop() {
        let read_dir = match fs::read_dir(&current) {
            Ok(rd) => rd,
            Err(err) => {
                errors.push(CustomRuleError::FileRead(current, err));
                continue;
            }
        };

        // The collected `files` vec is sorted before reading, so any
        // intra-directory order is fine here — iterate the read_dir lazily.
        for entry in read_dir.flatten() {
            let path = entry.path();

            // is_symlink uses symlink_metadata under the hood — does not
            // follow. We need this BEFORE deciding whether to descend.
            let is_symlink = entry
                .file_type()
                .map(|ft| ft.is_symlink())
                .unwrap_or_else(|_| path.is_symlink());

            // Resolve to a canonical target for symlinks; for regular paths
            // the canonical path is the same as canonicalize on the literal.
            // Either way we need the canonical for in-tree check + dedup.
            let canonical_target = match fs::canonicalize(&path) {
                Ok(t) => t,
                Err(err) => {
                    errors.push(CustomRuleError::FileRead(path.clone(), err));
                    continue;
                }
            };

            // Apply the in-tree-symlink protection at every step of the
            // recursion (lifted from the original shallow loader).
            if is_symlink {
                let in_tree = canonical_target.starts_with(&canonical_dir);
                if !in_tree {
                    if allow_external_symlinks {
                        eprintln!(
                            "WARNING: following external symlink {} → {} (allowed by --invariants-allow-external-symlinks)",
                            path.display(),
                            canonical_target.display()
                        );
                    } else {
                        errors.push(CustomRuleError::SymlinkOutsideDir {
                            link: path,
                            target: canonical_target,
                        });
                        continue;
                    }
                } else {
                    eprintln!(
                        "WARNING: following symlink {} → {}",
                        path.display(),
                        canonical_target.display()
                    );
                }
            }

            // Classify by the resolved target's metadata. `metadata()`
            // follows symlinks, which is what we want here.
            let meta = match fs::metadata(&path) {
                Ok(m) => m,
                Err(err) => {
                    errors.push(CustomRuleError::FileRead(path.clone(), err));
                    continue;
                }
            };

            if meta.is_dir() {
                // Cycle protection: only descend into a directory whose
                // canonical path we have not seen yet.
                if visited_dirs.insert(canonical_target.clone()) {
                    stack.push(path);
                }
                continue;
            }

            if !meta.is_file() {
                continue;
            }
            match path.extension().and_then(|e| e.to_str()) {
                Some("yml") | Some("yaml") => {}
                _ => continue,
            }

            // Dedup: first sighting wins, so the literal path stamped into
            // `source_file` is the one DFS reached first.
            if !seen.insert(canonical_target.clone()) {
                eprintln!(
                    "WARNING: symlink {} resolved to the same file already loaded; skipping",
                    path.display()
                );
                continue;
            }
            files.push((path, canonical_target));
        }
    }

    // Sort by literal path so rule order is deterministic regardless of
    // filesystem readdir order or DFS traversal order.
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut rules = Vec::new();
    for (path, _canonical) in files {
        match read_to_string_capped(&path) {
            Ok(content) => match parse_rules_multi_doc_with_source(&content, Some(&path)) {
                Ok(mut parsed) => rules.append(&mut parsed),
                Err(err) => errors.push(CustomRuleError::YamlParse(path, err)),
            },
            Err(err) => errors.push(err),
        }
    }

    if errors.is_empty() {
        Ok(rules)
    } else {
        Err(errors)
    }
}

fn read_to_string_capped(path: &Path) -> Result<String, CustomRuleError> {
    let metadata = fs::metadata(path).map_err(|err| CustomRuleError::FileRead(path.into(), err))?;
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(CustomRuleError::FileTooLarge {
            path: path.into(),
            max_bytes: MAX_INPUT_BYTES,
            actual_bytes: metadata.len(),
        });
    }
    let content =
        fs::read_to_string(path).map_err(|err| CustomRuleError::FileRead(path.into(), err))?;
    if content.len() as u64 > MAX_INPUT_BYTES {
        return Err(CustomRuleError::FileTooLarge {
            path: path.into(),
            max_bytes: MAX_INPUT_BYTES,
            actual_bytes: content.len() as u64,
        });
    }
    Ok(content)
}

/// Parse a YAML string containing one or more `CustomRule` documents (separated
/// by `---`). Single-doc files behave identically to the legacy
/// `serde_yaml::from_str::<CustomRule>` path. Empty/whitespace-only documents
/// (e.g. a leading `---` followed by a real doc) are skipped.
///
/// Equivalent to `parse_rules_multi_doc_with_source(content, None)` — provenance
/// stamping is opt-in via the `_with_source` variant so callers that don't
/// know the originating path (tests, stdin) keep working unchanged.
pub fn parse_rules_multi_doc(content: &str) -> Result<Vec<CustomRule>, serde_yaml::Error> {
    parse_rules_multi_doc_with_source(content, None)
}

/// Parse one or more `CustomRule` documents from `content` and stamp every
/// produced rule with `source_file = source` so downstream finding emission
/// can attribute authority back to the originating YAML file. Used by
/// `load_rules_dir` to thread file paths through into `FindingSource::Custom`.
pub fn parse_rules_multi_doc_with_source(
    content: &str,
    source: Option<&Path>,
) -> Result<Vec<CustomRule>, serde_yaml::Error> {
    let mut rules = Vec::new();
    for doc in serde_yaml::Deserializer::from_str(content) {
        // An empty document deserializes as `Value::Null`; skip those so a
        // leading `---` or trailing separator doesn't break the load.
        let value = serde_yaml::Value::deserialize(doc)?;
        if value.is_null() {
            continue;
        }
        let mut rule: CustomRule = serde_yaml::from_value(value)?;
        rule.source_file = source.map(|p| p.to_path_buf());
        rules.push(rule);
    }
    Ok(rules)
}

impl NodeMatcher {
    fn matches(&self, node: &crate::graph::Node) -> bool {
        if let Some(kinds) = &self.node_type {
            if !kinds.contains(&node.kind) {
                return false;
            }
        }
        if let Some(zones) = &self.trust_zone {
            if !zones.contains(&node.trust_zone) {
                return false;
            }
        }
        if !self.metadata.matches(&node.metadata) {
            return false;
        }
        if let Some(inner) = &self.not {
            if inner.matches(node) {
                return false;
            }
        }
        true
    }

    /// True when the matcher has no constraints — used by tests/tooling.
    #[allow(dead_code)]
    fn is_wildcard(&self) -> bool {
        self.node_type.is_none()
            && self.trust_zone.is_none()
            && self.metadata.is_empty()
            && self.not.is_none()
    }
}

impl PathMatcher {
    fn matches(&self, path: &PropagationPath) -> bool {
        if self.crosses_to.is_empty() {
            return true;
        }
        match path.boundary_crossing {
            Some((_, to_zone)) => self.crosses_to.contains(&to_zone),
            None => false,
        }
    }
}

/// Evaluate every (rule, path) pair. A finding is produced when the rule's
/// source, sink, and path predicates all match. Findings carry the rule id in
/// the message so operators can trace back to the originating YAML.
pub fn evaluate_custom_rules(
    graph: &AuthorityGraph,
    paths: &[PropagationPath],
    rules: &[CustomRule],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        // Standalone (node-shape-only) mode: when `standalone:` is present,
        // walk every node in the graph and emit one finding per match. The
        // source/sink/path fields are ignored, but `graph_metadata:` still
        // gates whether the rule runs at all — that's how PR-context
        // assertions on node shape work.
        if let Some(matcher) = &rule.match_spec.standalone {
            if !rule.match_spec.graph_metadata.matches(&graph.metadata) {
                continue;
            }
            for node in &graph.nodes {
                if !matcher.matches(node) {
                    continue;
                }
                findings.push(Finding {
                    severity: rule.severity,
                    category: rule.category,
                    nodes_involved: vec![node.id],
                    message: format!("[{}] {}: {}", rule.id, rule.name, node.name),
                    recommendation: Recommendation::Manual {
                        action: if rule.description.is_empty() {
                            format!("Review custom rule '{}'", rule.id)
                        } else {
                            rule.description.clone()
                        },
                    },
                    path: None,
                    source: custom_source(rule),
                    extras: FindingExtras::default(),
                });
            }
            continue;
        }

        // Graph-level metadata gate: if the predicate doesn't hold against
        // `graph.metadata`, no path in this graph can match this rule. Skip
        // the path loop entirely. An empty `graph_metadata:` (the common case
        // for rules that don't care about graph-level state) trivially matches.
        if !rule.match_spec.graph_metadata.matches(&graph.metadata) {
            continue;
        }

        for path in paths {
            let source_node = match graph.node(path.source) {
                Some(n) => n,
                None => continue,
            };
            let sink_node = match graph.node(path.sink) {
                Some(n) => n,
                None => continue,
            };

            if !rule.match_spec.source.matches(source_node) {
                continue;
            }
            if !rule.match_spec.sink.matches(sink_node) {
                continue;
            }
            if !rule.match_spec.path.matches(path) {
                continue;
            }

            findings.push(Finding {
                severity: rule.severity,
                category: rule.category,
                nodes_involved: vec![path.source, path.sink],
                message: format!(
                    "[{}] {}: {} -> {}",
                    rule.id, rule.name, source_node.name, sink_node.name
                ),
                recommendation: Recommendation::Manual {
                    action: if rule.description.is_empty() {
                        format!("Review custom rule '{}'", rule.id)
                    } else {
                        rule.description.clone()
                    },
                },
                path: Some(path.clone()),
                source: custom_source(rule),
                extras: FindingExtras::default(),
            });
        }
    }

    findings
}

/// Build a `FindingSource::Custom` from the rule's tracked YAML path. Falls
/// back to an empty path when the rule was constructed in-memory (test,
/// stdin) and never carried provenance — those callers already know the
/// finding is custom; the empty path just makes that obvious.
fn custom_source(rule: &CustomRule) -> FindingSource {
    FindingSource::Custom {
        source_file: rule.source_file.clone().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{AuthorityGraph, EdgeKind, PipelineSource};
    use crate::propagation::{propagation_analysis, DEFAULT_MAX_HOPS};

    fn source() -> PipelineSource {
        PipelineSource {
            file: "test.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        }
    }

    fn build_graph_with_paths() -> (AuthorityGraph, Vec<PropagationPath>) {
        let mut g = AuthorityGraph::new(source());
        let secret = g.add_node(NodeKind::Secret, "API_KEY", TrustZone::FirstParty);
        let trusted = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let untrusted = g.add_node(NodeKind::Step, "third-party", TrustZone::Untrusted);

        g.add_edge(trusted, secret, EdgeKind::HasAccessTo);
        g.add_edge(trusted, untrusted, EdgeKind::DelegatesTo);

        let paths = propagation_analysis(&g, DEFAULT_MAX_HOPS);
        (g, paths)
    }

    fn one<T>(v: T) -> Option<OneOrMany<T>> {
        Some(OneOrMany::One(v))
    }

    #[test]
    fn custom_rule_fires_on_matching_path() {
        let (graph, paths) = build_graph_with_paths();

        let rule = CustomRule {
            id: "secret_to_untrusted".into(),
            name: "Secret reaching untrusted step".into(),
            description: "Custom policy".into(),
            severity: Severity::Critical,
            category: FindingCategory::AuthorityPropagation,
            match_spec: MatchSpec {
                source: NodeMatcher {
                    node_type: None,
                    trust_zone: one(TrustZone::FirstParty),
                    metadata: MetadataMatcher::default(),
                    not: None,
                },
                sink: NodeMatcher {
                    node_type: None,
                    trust_zone: one(TrustZone::Untrusted),
                    metadata: MetadataMatcher::default(),
                    not: None,
                },
                path: PathMatcher::default(),
                graph_metadata: MetadataMatcher::default(),
                standalone: None,
            },
            source_file: None,
        };

        let findings = evaluate_custom_rules(&graph, &paths, &[rule]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].message.contains("secret_to_untrusted"));
    }

    #[test]
    fn custom_rule_does_not_fire_when_predicates_miss() {
        let (graph, paths) = build_graph_with_paths();

        let rule = CustomRule {
            id: "miss".into(),
            name: "Untrusted source".into(),
            description: String::new(),
            severity: Severity::Critical,
            category: FindingCategory::AuthorityPropagation,
            match_spec: MatchSpec {
                source: NodeMatcher {
                    node_type: None,
                    trust_zone: one(TrustZone::Untrusted),
                    metadata: MetadataMatcher::default(),
                    not: None,
                },
                sink: NodeMatcher::default(),
                path: PathMatcher::default(),
                graph_metadata: MetadataMatcher::default(),
                standalone: None,
            },
            source_file: None,
        };

        let findings = evaluate_custom_rules(&graph, &paths, &[rule]);
        assert!(findings.is_empty());
    }

    #[test]
    fn yaml_round_trip_loads_full_rule() {
        let yaml = r#"
id: my_secret_to_untrusted
name: Secret reaching untrusted step
description: "Custom policy: secrets must not reach untrusted steps"
severity: critical
category: authority_propagation
match:
  source:
    node_type: secret
    trust_zone: first_party
  sink:
    node_type: step
    trust_zone: untrusted
  path:
    crosses_to: [untrusted]
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml must parse");
        assert_eq!(rule.id, "my_secret_to_untrusted");
        assert_eq!(rule.severity, Severity::Critical);
        assert!(matches!(
            rule.match_spec.source.node_type,
            Some(OneOrMany::One(NodeKind::Secret))
        ));
        assert!(matches!(
            rule.match_spec.sink.trust_zone,
            Some(OneOrMany::One(TrustZone::Untrusted))
        ));
        assert_eq!(rule.match_spec.path.crosses_to, vec![TrustZone::Untrusted]);
    }

    #[test]
    fn metadata_predicate_must_match_all_keys() {
        let mut g = AuthorityGraph::new(source());
        let mut meta = HashMap::new();
        meta.insert("kind".to_string(), "deploy".to_string());
        let secret =
            g.add_node_with_metadata(NodeKind::Secret, "TOKEN", TrustZone::FirstParty, meta);
        let sink = g.add_node(NodeKind::Step, "remote", TrustZone::Untrusted);
        let step = g.add_node(NodeKind::Step, "use", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);
        g.add_edge(step, sink, EdgeKind::DelegatesTo);

        let paths = propagation_analysis(&g, DEFAULT_MAX_HOPS);

        let mut want_fields = HashMap::new();
        want_fields.insert(
            "kind".to_string(),
            MetadataPredicate::Equals("deploy".to_string()),
        );
        let hit = CustomRule {
            id: "hit".into(),
            name: "n".into(),
            description: String::new(),
            severity: Severity::High,
            category: FindingCategory::AuthorityPropagation,
            match_spec: MatchSpec {
                source: NodeMatcher {
                    node_type: one(NodeKind::Secret),
                    trust_zone: None,
                    metadata: MetadataMatcher {
                        fields: want_fields,
                        not: None,
                    },
                    not: None,
                },
                sink: NodeMatcher::default(),
                path: PathMatcher::default(),
                graph_metadata: MetadataMatcher::default(),
                standalone: None,
            },
            source_file: None,
        };
        assert_eq!(evaluate_custom_rules(&g, &paths, &[hit]).len(), 1);

        let mut wrong_fields = HashMap::new();
        wrong_fields.insert(
            "kind".to_string(),
            MetadataPredicate::Equals("build".to_string()),
        );
        let miss = CustomRule {
            id: "miss".into(),
            name: "n".into(),
            description: String::new(),
            severity: Severity::High,
            category: FindingCategory::AuthorityPropagation,
            match_spec: MatchSpec {
                source: NodeMatcher {
                    node_type: one(NodeKind::Secret),
                    trust_zone: None,
                    metadata: MetadataMatcher {
                        fields: wrong_fields,
                        not: None,
                    },
                    not: None,
                },
                sink: NodeMatcher::default(),
                path: PathMatcher::default(),
                graph_metadata: MetadataMatcher::default(),
                standalone: None,
            },
            source_file: None,
        };
        assert!(evaluate_custom_rules(&g, &paths, &[miss]).is_empty());
    }

    #[test]
    fn load_rules_dir_reads_yml_and_yaml() {
        let tmp = std::env::temp_dir().join(format!("taudit-custom-rules-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        let yml_path = tmp.join("a.yml");
        let yaml_path = tmp.join("b.yaml");
        let other_path = tmp.join("c.txt");

        fs::write(
            &yml_path,
            "id: a\nname: a\nseverity: high\ncategory: authority_propagation\n",
        )
        .unwrap();
        fs::write(
            &yaml_path,
            "id: b\nname: b\nseverity: medium\ncategory: unpinned_action\n",
        )
        .unwrap();
        fs::write(&other_path, "ignored").unwrap();

        let rules = load_rules_dir(&tmp).expect("load must succeed");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "a");
        assert_eq!(rules[1].id, "b");

        // cleanup
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_rules_dir_reports_yaml_errors_with_path() {
        let tmp =
            std::env::temp_dir().join(format!("taudit-custom-rules-bad-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        let bad = tmp.join("bad.yml");
        fs::write(&bad, "id: x\nseverity: not-a-real-severity\n").unwrap();

        let errs = load_rules_dir(&tmp).expect_err("should fail");
        assert_eq!(errs.len(), 1);
        let msg = errs[0].to_string();
        assert!(msg.contains("bad.yml"), "error must mention path: {msg}");

        let _ = fs::remove_dir_all(&tmp);
    }

    /// `EgressBlindspot` and `MissingAuditTrail` carry
    /// `#[serde(skip_deserializing)]` because they cannot be detected from
    /// pipeline YAML alone — they need runtime telemetry / external audit
    /// configuration. A custom-rule YAML that names either of those
    /// categories must therefore fail to load with a clear `unknown variant`
    /// error from serde, even though the variants still serialise normally
    /// and remain valid in OUTPUT schemas.
    #[test]
    fn reserved_categories_rejected_by_custom_rule_loader() {
        let tmp = std::env::temp_dir().join(format!(
            "taudit-custom-rules-reserved-{}",
            std::process::id()
        ));
        fs::create_dir_all(&tmp).unwrap();
        let reserved_path = tmp.join("reserved.yml");
        fs::write(
            &reserved_path,
            "id: r\nname: r\nseverity: high\ncategory: egress_blindspot\n",
        )
        .unwrap();

        let errs = load_rules_dir(&tmp).expect_err("reserved category must be rejected");
        assert_eq!(errs.len(), 1);
        let msg = errs[0].to_string();
        assert!(
            msg.contains("unknown variant") && msg.contains("egress_blindspot"),
            "expected an `unknown variant `egress_blindspot`` error, got: {msg}"
        );

        // Same for the second reserved variant.
        let other_path = tmp.join("reserved2.yml");
        fs::write(
            &other_path,
            "id: r2\nname: r2\nseverity: high\ncategory: missing_audit_trail\n",
        )
        .unwrap();
        let errs2 = load_rules_dir(&tmp).expect_err("second reserved category must be rejected");
        // Both files are bad now — each surfaces its own error.
        assert!(errs2.iter().any(|e| {
            let m = e.to_string();
            m.contains("unknown variant") && m.contains("missing_audit_trail")
        }));

        let _ = fs::remove_dir_all(&tmp);
    }

    /// Constructive seal contract: even though serde refuses to
    /// deserialise the reserved variants, the Rust enum can still
    /// construct them (e.g. for runtime-enrichment paths) and they MUST
    /// serialise verbatim to their snake_case form. This is what makes
    /// it correct for the OUTPUT schemas to advertise them.
    #[test]
    fn reserved_categories_still_serialize_when_constructed_in_rust() {
        let f = Finding {
            severity: Severity::Medium,
            category: FindingCategory::EgressBlindspot,
            path: None,
            nodes_involved: vec![],
            message: "runtime-enriched".into(),
            recommendation: Recommendation::Manual {
                action: "investigate".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        };
        let json = serde_json::to_value(&f).expect("serialises fine");
        assert_eq!(json["category"], "egress_blindspot");

        let g = Finding {
            category: FindingCategory::MissingAuditTrail,
            ..f
        };
        let json2 = serde_json::to_value(&g).expect("serialises fine");
        assert_eq!(json2["category"], "missing_audit_trail");
    }

    // ── v0.6 grammar additions: negation + typed metadata predicates ─────

    /// Build a graph with one secret in first_party reaching one untrusted
    /// step. Used by the new grammar tests.
    fn simple_first_to_untrusted_graph() -> (AuthorityGraph, Vec<PropagationPath>) {
        let mut g = AuthorityGraph::new(source());
        let mut meta = HashMap::new();
        meta.insert("oidc".to_string(), "true".to_string());
        meta.insert("permissions".to_string(), "contents: write".to_string());
        meta.insert("role".to_string(), "admin".to_string());
        let secret =
            g.add_node_with_metadata(NodeKind::Identity, "GH_TOKEN", TrustZone::FirstParty, meta);
        let step = g.add_node(NodeKind::Step, "use-it", TrustZone::FirstParty);
        let untrusted = g.add_node(NodeKind::Step, "third-party", TrustZone::Untrusted);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);
        g.add_edge(step, untrusted, EdgeKind::DelegatesTo);
        let paths = propagation_analysis(&g, DEFAULT_MAX_HOPS);
        (g, paths)
    }

    #[test]
    fn negation_on_trust_zone_inverts_match() {
        let (graph, paths) = simple_first_to_untrusted_graph();
        // sink is untrusted; "not untrusted" must NOT match the sink → no findings
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  sink:
    not:
      trust_zone: untrusted
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        assert!(evaluate_custom_rules(&graph, &paths, &[rule]).is_empty());
    }

    #[test]
    fn negation_on_node_type_list_matches_other_kinds() {
        let (graph, paths) = simple_first_to_untrusted_graph();
        // source kinds in fixtures: identity. "not [secret, identity]" excludes it
        // → source predicate fails → no findings.
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    not:
      node_type: [secret, identity]
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        assert!(evaluate_custom_rules(&graph, &paths, &[rule]).is_empty());

        // Inverse: "not [step]" — source is identity, so the inner does NOT match,
        // therefore the not-wrapper matches → at least one finding fires.
        let yaml2 = r#"
id: r2
name: r2
severity: high
category: authority_propagation
match:
  source:
    not:
      node_type: [step]
"#;
        let rule2: CustomRule = serde_yaml::from_str(yaml2).expect("yaml parses");
        assert!(!evaluate_custom_rules(&graph, &paths, &[rule2]).is_empty());
    }

    #[test]
    fn metadata_negation_matches_absent_or_other_value() {
        let (graph, paths) = simple_first_to_untrusted_graph();
        // The identity has oidc=true. `not: { oidc: "true" }` excludes it →
        // no finding when applied to the source.
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    metadata:
      not:
        oidc: "true"
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        assert!(evaluate_custom_rules(&graph, &paths, &[rule]).is_empty());
    }

    #[test]
    fn metadata_contains_does_substring_match() {
        let (graph, paths) = simple_first_to_untrusted_graph();
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    metadata:
      permissions:
        contains: "contents: write"
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        assert_eq!(evaluate_custom_rules(&graph, &paths, &[rule]).len(), 1);

        // negative case: substring not present
        let yaml_miss = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    metadata:
      permissions:
        contains: "actions: write"
"#;
        let rule_miss: CustomRule = serde_yaml::from_str(yaml_miss).expect("yaml parses");
        assert!(evaluate_custom_rules(&graph, &paths, &[rule_miss]).is_empty());
    }

    #[test]
    fn metadata_in_matches_any_of_allowed_values() {
        let (graph, paths) = simple_first_to_untrusted_graph();
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    metadata:
      role:
        in: [admin, owner, write]
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        assert_eq!(evaluate_custom_rules(&graph, &paths, &[rule]).len(), 1);

        let yaml_miss = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    metadata:
      role:
        in: [reader, none]
"#;
        let rule_miss: CustomRule = serde_yaml::from_str(yaml_miss).expect("yaml parses");
        assert!(evaluate_custom_rules(&graph, &paths, &[rule_miss]).is_empty());
    }

    #[test]
    fn metadata_not_equals_excludes_specific_value() {
        let (graph, paths) = simple_first_to_untrusted_graph();
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    metadata:
      role:
        not_equals: admin
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        // role=admin → not_equals fails → no findings
        assert!(evaluate_custom_rules(&graph, &paths, &[rule]).is_empty());

        let yaml_hit = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    metadata:
      role:
        not_equals: reader
"#;
        let rule_hit: CustomRule = serde_yaml::from_str(yaml_hit).expect("yaml parses");
        assert_eq!(evaluate_custom_rules(&graph, &paths, &[rule_hit]).len(), 1);
    }

    #[test]
    fn nested_not_collapses_to_inner_condition() {
        let (graph, paths) = simple_first_to_untrusted_graph();
        // not(not(trust_zone=first_party)) ≡ trust_zone=first_party.
        // The source is first_party so this should fire.
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    not:
      not:
        trust_zone: first_party
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        assert!(!evaluate_custom_rules(&graph, &paths, &[rule]).is_empty());
    }

    #[test]
    fn node_type_accepts_single_value_back_compat() {
        // The original v0.4 simple form must still parse and behave identically.
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    node_type: identity
    trust_zone: first_party
    metadata:
      oidc: "true"
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("v0.4 form must still parse");
        assert!(matches!(
            rule.match_spec.source.node_type,
            Some(OneOrMany::One(NodeKind::Identity))
        ));
        assert!(matches!(
            rule.match_spec.source.trust_zone,
            Some(OneOrMany::One(TrustZone::FirstParty))
        ));
        let pred = rule
            .match_spec
            .source
            .metadata
            .fields
            .get("oidc")
            .expect("oidc predicate");
        assert!(matches!(pred, MetadataPredicate::Equals(v) if v == "true"));

        let (graph, paths) = simple_first_to_untrusted_graph();
        assert_eq!(evaluate_custom_rules(&graph, &paths, &[rule]).len(), 1);
    }

    #[test]
    fn node_type_accepts_list_form() {
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    node_type: [secret, identity]
    trust_zone: [first_party, third_party]
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("list form must parse");
        match &rule.match_spec.source.node_type {
            Some(OneOrMany::Many(v)) => {
                assert_eq!(v, &vec![NodeKind::Secret, NodeKind::Identity]);
            }
            other => panic!("expected list form, got {other:?}"),
        }
        let (graph, paths) = simple_first_to_untrusted_graph();
        assert_eq!(evaluate_custom_rules(&graph, &paths, &[rule]).len(), 1);
    }

    // ── Gap B: graph-level metadata predicates ──────────────

    /// Builds a graph with one PR-context source/sink path and lets tests set
    /// graph-level metadata to pressure-test the new predicate.
    fn pr_context_graph_with_meta(meta: &[(&str, &str)]) -> (AuthorityGraph, Vec<PropagationPath>) {
        let mut g = AuthorityGraph::new(source());
        let mut secret_meta = HashMap::new();
        secret_meta.insert("variable_group".to_string(), "true".to_string());
        let secret = g.add_node_with_metadata(
            NodeKind::Secret,
            "VG_SECRET",
            TrustZone::FirstParty,
            secret_meta,
        );
        let step = g.add_node(NodeKind::Step, "use", TrustZone::FirstParty);
        let untrusted = g.add_node(NodeKind::Step, "third-party", TrustZone::Untrusted);
        g.add_edge(step, secret, crate::graph::EdgeKind::HasAccessTo);
        g.add_edge(step, untrusted, crate::graph::EdgeKind::DelegatesTo);
        for (k, v) in meta {
            g.metadata.insert((*k).to_string(), (*v).to_string());
        }
        let paths = propagation_analysis(&g, DEFAULT_MAX_HOPS);
        (g, paths)
    }

    #[test]
    fn graph_metadata_equals_matches_when_value_present() {
        let (graph, paths) = pr_context_graph_with_meta(&[("trigger", "pr")]);
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  graph_metadata:
    trigger:
      equals: pr
  source:
    metadata:
      variable_group: "true"
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        assert_eq!(evaluate_custom_rules(&graph, &paths, &[rule]).len(), 1);
    }

    #[test]
    fn graph_metadata_in_matches_any_of_listed_values() {
        let (graph, paths) = pr_context_graph_with_meta(&[("trigger", "merge_request_event")]);
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  graph_metadata:
    trigger:
      in: [pull_request_target, pr, merge_request_event]
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        assert!(!evaluate_custom_rules(&graph, &paths, &[rule]).is_empty());
    }

    #[test]
    fn graph_metadata_negation_excludes_unwanted_trigger() {
        // graph trigger=push, rule wants "not push" → must NOT fire.
        let (graph, paths) = pr_context_graph_with_meta(&[("trigger", "push")]);
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  graph_metadata:
    not:
      trigger:
        equals: push
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        assert!(evaluate_custom_rules(&graph, &paths, &[rule]).is_empty());

        // Inverse: trigger=pr, rule wants "not push" → fires.
        let (graph2, paths2) = pr_context_graph_with_meta(&[("trigger", "pr")]);
        let rule2: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        assert!(!evaluate_custom_rules(&graph2, &paths2, &[rule2]).is_empty());
    }

    #[test]
    fn graph_metadata_missing_key_does_not_match_no_crash() {
        // Graph has no `trigger` metadata at all. `equals: pr` requires the key
        // to be present with that value → no findings, no panic.
        let (graph, paths) = pr_context_graph_with_meta(&[]);
        assert!(!graph.metadata.contains_key("trigger"));
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  graph_metadata:
    trigger:
      equals: pr
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        let findings = evaluate_custom_rules(&graph, &paths, &[rule]);
        assert!(findings.is_empty(), "missing key must yield no findings");
    }

    #[test]
    fn rules_without_graph_metadata_remain_backward_compatible() {
        // No `graph_metadata:` block → trivially matches regardless of graph
        // state. This is the v0.4-v0.9 behaviour and must keep working.
        let (graph, paths) = pr_context_graph_with_meta(&[("trigger", "anything")]);
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    metadata:
      variable_group: "true"
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        assert_eq!(evaluate_custom_rules(&graph, &paths, &[rule]).len(), 1);
    }

    // ── Gap C: image sinks + standalone node predicates ─────

    /// Builds a graph with one Identity → Step → Image (Untrusted) chain.
    /// The Image node is reached via `UsesImage` so propagation_analysis
    /// produces a path whose sink is the Image — this is what lets custom
    /// rules use `sink: { node_type: image }`.
    fn graph_with_image_sink() -> (AuthorityGraph, Vec<PropagationPath>) {
        let mut g = AuthorityGraph::new(source());
        let identity = g.add_node(NodeKind::Identity, "GH_TOKEN", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "publish", TrustZone::FirstParty);
        let image = g.add_node(
            NodeKind::Image,
            "third-party/deploy@v1",
            TrustZone::Untrusted,
        );
        g.add_edge(step, identity, crate::graph::EdgeKind::HasAccessTo);
        g.add_edge(step, image, crate::graph::EdgeKind::UsesImage);
        let paths = propagation_analysis(&g, DEFAULT_MAX_HOPS);
        (g, paths)
    }

    #[test]
    fn sink_node_type_image_matches_image_path_endpoint() {
        let (graph, paths) = graph_with_image_sink();
        let yaml = r#"
id: r
name: r
severity: high
category: untrusted_with_authority
match:
  sink:
    node_type: image
    trust_zone: untrusted
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        let findings = evaluate_custom_rules(&graph, &paths, &[rule]);
        assert!(
            !findings.is_empty(),
            "Image-as-sink must produce at least one finding"
        );
    }

    #[test]
    fn standalone_matches_every_floating_image_in_graph() {
        // Two Image nodes: one floating (no `digest` metadata), one digest-pinned.
        let mut g = AuthorityGraph::new(source());
        let _step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let _floating1 = g.add_node(NodeKind::Image, "alpine:latest", TrustZone::ThirdParty);
        let _floating2 = g.add_node(NodeKind::Image, "ubuntu:22.04", TrustZone::ThirdParty);
        let mut pinned_meta = HashMap::new();
        pinned_meta.insert("digest".to_string(), "sha256:abc".to_string());
        let _pinned = g.add_node_with_metadata(
            NodeKind::Image,
            "alpine@sha256:abc",
            TrustZone::ThirdParty,
            pinned_meta,
        );
        // Propagation paths irrelevant for standalone mode.
        let paths: Vec<PropagationPath> = Vec::new();

        let yaml = r#"
id: floating_image_standalone
name: Floating image
severity: medium
category: unpinned_action
match:
  standalone:
    node_type: image
    not:
      metadata:
        digest:
          contains: "sha256:"
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        let findings = evaluate_custom_rules(&g, &paths, &[rule]);
        assert_eq!(
            findings.len(),
            2,
            "standalone must fire once per floating Image node"
        );
    }

    #[test]
    fn standalone_supports_in_operator() {
        let mut g = AuthorityGraph::new(source());
        let mut self_hosted_meta = HashMap::new();
        self_hosted_meta.insert("self_hosted".to_string(), "true".to_string());
        let _pool = g.add_node_with_metadata(
            NodeKind::Image,
            "self-pool",
            TrustZone::FirstParty,
            self_hosted_meta,
        );
        let _hosted = g.add_node(NodeKind::Image, "ubuntu-latest", TrustZone::ThirdParty);
        let paths: Vec<PropagationPath> = Vec::new();

        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  standalone:
    node_type: image
    metadata:
      self_hosted:
        in: ["true", "yes"]
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        let findings = evaluate_custom_rules(&g, &paths, &[rule]);
        assert_eq!(findings.len(), 1, "in:[\"true\",\"yes\"] matches one node");
    }

    #[test]
    fn standalone_still_honors_graph_metadata_gate() {
        // Standalone bypasses source/sink/path but `graph_metadata:` remains
        // a precondition — that's how PR-context node-shape rules work.
        let mut g_pr = AuthorityGraph::new(source());
        g_pr.metadata.insert("trigger".into(), "pr".into());
        g_pr.add_node(NodeKind::Image, "alpine:latest", TrustZone::ThirdParty);

        let mut g_push = AuthorityGraph::new(source());
        g_push.metadata.insert("trigger".into(), "push".into());
        g_push.add_node(NodeKind::Image, "alpine:latest", TrustZone::ThirdParty);

        let yaml = r#"
id: r
name: r
severity: low
category: unpinned_action
match:
  graph_metadata:
    trigger:
      equals: pr
  standalone:
    node_type: image
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        assert_eq!(
            evaluate_custom_rules(&g_pr, &[], std::slice::from_ref(&rule)).len(),
            1,
            "fires on PR graph"
        );
        assert!(
            evaluate_custom_rules(&g_push, &[], std::slice::from_ref(&rule)).is_empty(),
            "graph_metadata gate must suppress on push graph"
        );
    }

    #[test]
    fn standalone_ignores_source_sink_path_fields() {
        // Even when source/sink would never match (no propagation paths exist),
        // standalone fires per node-shape match. Documents the precedence rule.
        let mut g = AuthorityGraph::new(source());
        let _img = g.add_node(NodeKind::Image, "alpine:latest", TrustZone::ThirdParty);
        let paths: Vec<PropagationPath> = Vec::new();

        let yaml = r#"
id: r
name: r
severity: low
category: unpinned_action
match:
  source:
    node_type: secret    # would never match anything in this graph
  standalone:
    node_type: image
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml parses");
        let findings = evaluate_custom_rules(&g, &paths, &[rule]);
        assert_eq!(findings.len(), 1);
    }

    // ── Gap A: multi-doc YAML loading ───────────────────────

    #[test]
    fn multi_doc_yaml_loads_each_document_as_separate_rule() {
        let yaml = r#"
id: rule_a
name: First rule
severity: high
category: authority_propagation
match:
  source:
    node_type: secret
---
id: rule_b
name: Second rule
severity: critical
category: untrusted_with_authority
match:
  sink:
    trust_zone: untrusted
---
id: rule_c
name: Third rule
severity: medium
category: unpinned_action
"#;
        let rules = parse_rules_multi_doc(yaml).expect("multi-doc must parse");
        assert_eq!(rules.len(), 3, "expected 3 rules from 3-doc YAML");
        assert_eq!(rules[0].id, "rule_a");
        assert_eq!(rules[1].id, "rule_b");
        assert_eq!(rules[2].id, "rule_c");
        assert_eq!(rules[1].severity, Severity::Critical);
    }

    #[test]
    fn single_doc_yaml_still_loads_identically() {
        let yaml = r#"
id: solo
name: Solo rule
severity: high
category: authority_propagation
"#;
        let rules = parse_rules_multi_doc(yaml).expect("single-doc must parse");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "solo");
    }

    #[test]
    fn multi_doc_with_empty_leading_document_is_skipped() {
        let yaml = r#"---
---
id: only
name: only
severity: low
category: authority_propagation
"#;
        let rules = parse_rules_multi_doc(yaml).expect("must parse");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "only");
    }

    #[test]
    fn load_rules_dir_loads_multi_doc_files() {
        let tmp =
            std::env::temp_dir().join(format!("taudit-custom-rules-multi-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("bundle.yml");
        fs::write(
            &path,
            r#"
id: a
name: a
severity: high
category: authority_propagation
---
id: b
name: b
severity: medium
category: unpinned_action
---
id: c
name: c
severity: low
category: authority_propagation
"#,
        )
        .unwrap();

        let rules = load_rules_dir(&tmp).expect("multi-doc file must load");
        assert_eq!(rules.len(), 3, "expected 3 rules from one bundled file");

        let _ = fs::remove_dir_all(&tmp);
    }

    // ── Provenance: every custom-rule finding carries source path ────────

    #[test]
    fn loaded_rule_threads_source_file_into_findings() {
        let tmp = std::env::temp_dir().join(format!("taudit-custom-prov-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("provenance.yml");
        fs::write(
            &path,
            r#"
id: from_disk
name: From disk
description: planted invariant
severity: critical
category: authority_propagation
match:
  source:
    trust_zone: first_party
  sink:
    trust_zone: untrusted
"#,
        )
        .unwrap();

        let rules = load_rules_dir(&tmp).expect("rules load");
        assert_eq!(rules.len(), 1);
        // The loader stamps source_file on the rule itself.
        assert_eq!(rules[0].source_file.as_deref(), Some(path.as_path()));

        let (graph, paths) = build_graph_with_paths();
        let findings = evaluate_custom_rules(&graph, &paths, &rules);
        assert_eq!(findings.len(), 1);
        match &findings[0].source {
            FindingSource::Custom { source_file } => {
                assert_eq!(
                    source_file, &path,
                    "custom finding must carry the YAML path it was loaded from"
                );
            }
            other => panic!("expected FindingSource::Custom, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn in_memory_custom_rule_emits_custom_source_with_empty_path() {
        // Rules constructed in-memory (tests, stdin pipelines) never go
        // through the loader and therefore have no source path — the finding
        // must still be tagged as Custom (not silently mistakable for built-in)
        // so any operator inspecting a SIEM alert immediately sees provenance.
        let (graph, paths) = build_graph_with_paths();
        let rule = CustomRule {
            id: "in_mem".into(),
            name: "in-memory".into(),
            description: String::new(),
            severity: Severity::High,
            category: FindingCategory::AuthorityPropagation,
            match_spec: MatchSpec::default(),
            source_file: None,
        };
        let findings = evaluate_custom_rules(&graph, &paths, &[rule]);
        assert!(!findings.is_empty(), "in-mem rule must still match");
        for f in &findings {
            match &f.source {
                FindingSource::Custom { source_file } => {
                    assert!(
                        source_file.as_os_str().is_empty(),
                        "in-mem custom rule emits Custom with empty path, not BuiltIn"
                    );
                }
                other => {
                    panic!("in-memory custom rule must still produce Custom source, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn unknown_metadata_operator_is_rejected() {
        let yaml = r#"
id: r
name: r
severity: high
category: authority_propagation
match:
  source:
    metadata:
      role:
        starts_with: adm
"#;
        let err = serde_yaml::from_str::<CustomRule>(yaml)
            .expect_err("unknown operator must be rejected");
        let msg = err.to_string();
        // serde_yaml's untagged-enum error doesn't always echo the unknown
        // field name; the important guarantee is that the parse fails (so
        // typos in operator names don't silently match nothing).
        assert!(
            msg.contains("metadata") || msg.contains("variant"),
            "parse should fail with a meaningful location: {msg}"
        );
    }

    // ── Symlink protection (red-team R2 #4) ─────────────────
    //
    // These tests use Unix symlinks. Skipped on Windows where the test
    // harness usually lacks SeCreateSymbolicLinkPrivilege.

    #[cfg(unix)]
    fn unique_tmp(prefix: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "taudit-symlink-{prefix}-{}-{n}",
            std::process::id()
        ))
    }

    #[cfg(unix)]
    fn write_minimal_rule(path: &Path, id: &str) {
        fs::write(
            path,
            format!("id: {id}\nname: {id}\nseverity: high\ncategory: authority_propagation\n"),
        )
        .unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn load_rules_dir_follows_in_tree_symlink_with_warning() {
        use std::os::unix::fs::symlink;

        let tmp = unique_tmp("intree");
        fs::create_dir_all(&tmp).unwrap();

        let real = tmp.join("real.yml");
        write_minimal_rule(&real, "in_tree");
        let link = tmp.join("alias.yml");
        symlink(&real, &link).unwrap();

        // Default opts: in-tree symlinks are followed BUT deduplicated by
        // canonical path so an alias and its target collapse to a single
        // rule load. This is the contract documented on
        // `load_rules_dir_with_opts`: "Files reached via multiple paths …
        // are deduplicated by canonical path so the same rule never fires
        // twice." Pre-v1.1 behaviour double-loaded.
        let rules = load_rules_dir(&tmp).expect("in-tree symlink must be loaded");
        assert_eq!(
            rules.len(),
            1,
            "expected 1 rule (alias deduped against real target), got {rules:?}"
        );
        assert_eq!(rules[0].id, "in_tree");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    #[cfg(unix)]
    fn load_rules_dir_refuses_out_of_tree_symlink_by_default() {
        use std::os::unix::fs::symlink;

        let tmp = unique_tmp("outoftree-refuse");
        fs::create_dir_all(&tmp).unwrap();

        let outside_dir = unique_tmp("outoftree-target");
        fs::create_dir_all(&outside_dir).unwrap();
        let outside_file = outside_dir.join("evil.yml");
        write_minimal_rule(&outside_file, "evil");

        let link = tmp.join("legit.yml");
        symlink(&outside_file, &link).unwrap();

        let errs = load_rules_dir(&tmp).expect_err("out-of-tree symlink must be refused");
        assert_eq!(errs.len(), 1);
        assert!(
            matches!(errs[0], CustomRuleError::SymlinkOutsideDir { .. }),
            "expected SymlinkOutsideDir, got {:?}",
            errs[0]
        );
        let msg = errs[0].to_string();
        assert!(
            msg.contains("legit.yml") && msg.contains("evil.yml"),
            "error should name both link and target: {msg}"
        );

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&outside_dir);
    }

    #[test]
    #[cfg(unix)]
    fn load_rules_dir_follows_out_of_tree_symlink_with_override() {
        use std::os::unix::fs::symlink;

        let tmp = unique_tmp("outoftree-override");
        fs::create_dir_all(&tmp).unwrap();

        let outside_dir = unique_tmp("outoftree-target-override");
        fs::create_dir_all(&outside_dir).unwrap();
        let outside_file = outside_dir.join("external.yml");
        write_minimal_rule(&outside_file, "external");

        let link = tmp.join("aliased.yml");
        symlink(&outside_file, &link).unwrap();

        let rules = load_rules_dir_with_opts(&tmp, true)
            .expect("override flag must allow external symlinks");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "external");

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&outside_dir);
    }

    // ── F4: recursive directory walk ────────────────────────

    #[test]
    fn load_rules_dir_walks_subdirectories() {
        // Operators organise rules into platform-specific subtrees like
        // `invariants/gha/`, `invariants/ado/`. Pre-v1.1 the loader used a
        // single `read_dir` and silently skipped every subdir. The recursive
        // DFS must pick rules out of `<root>/sub/rule.yml`.
        let tmp = std::env::temp_dir().join(format!(
            "taudit-custom-rules-recursive-{}",
            std::process::id()
        ));
        let sub = tmp.join("sub");
        fs::create_dir_all(&sub).unwrap();

        let nested = sub.join("rule.yml");
        fs::write(
            &nested,
            "id: nested\nname: nested\nseverity: high\ncategory: authority_propagation\n",
        )
        .unwrap();

        let rules = load_rules_dir(&tmp).expect("recursive walk must load nested rule");
        assert_eq!(
            rules.len(),
            1,
            "expected 1 rule from nested dir, got {rules:?}"
        );
        assert_eq!(rules[0].id, "nested");

        let _ = fs::remove_dir_all(&tmp);
    }

    // ── F5: in-tree symlink dedup via canonical path ────────

    #[test]
    #[cfg(unix)]
    fn load_rules_dir_dedupes_in_tree_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = unique_tmp("dedup");
        fs::create_dir_all(&tmp).unwrap();

        let real = tmp.join("real.yml");
        write_minimal_rule(&real, "dedup_target");
        let alias = tmp.join("alias.yml");
        symlink(&real, &alias).unwrap();

        // The alias canonicalises to the same path as `real.yml`. Loader
        // must collapse to ONE rule (and emit a warning to stderr — we
        // don't capture stderr in unit tests, but we assert the visible
        // contract of single-load).
        let rules = load_rules_dir(&tmp).expect("alias dedup must succeed");
        assert_eq!(rules.len(), 1, "expected 1 rule after dedup, got {rules:?}");
        assert_eq!(rules[0].id, "dedup_target");

        let _ = fs::remove_dir_all(&tmp);
    }

    // ── F6: id validation contract ──────────────────────────

    #[test]
    fn custom_rule_id_validation_rejects_empty() {
        let yaml = r#"
id: ""
name: x
severity: high
category: authority_propagation
"#;
        let err = serde_yaml::from_str::<CustomRule>(yaml).expect_err("empty id must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("non-empty"),
            "error must explain why empty fails: {msg}"
        );
    }

    #[test]
    fn custom_rule_id_validation_rejects_brackets() {
        let yaml = r#"
id: "foo] [bar"
name: x
severity: high
category: authority_propagation
"#;
        let err =
            serde_yaml::from_str::<CustomRule>(yaml).expect_err("bracket in id must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("foo] [bar") && msg.contains("invalid character"),
            "error must name the offending id and the invalid character: {msg}"
        );
        // Specifically calls out a bracket character (could be ']' or '[' —
        // the loop hits ']' first since it's at index 3 of `foo] [bar`).
        assert!(
            msg.contains("']'") || msg.contains("'['") || msg.contains("' '"),
            "error should quote the first offending character: {msg}"
        );
    }

    #[test]
    fn custom_rule_id_validation_rejects_whitespace() {
        let yaml = r#"
id: "foo bar"
name: x
severity: high
category: authority_propagation
"#;
        let err = serde_yaml::from_str::<CustomRule>(yaml)
            .expect_err("whitespace in id must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("foo bar") && msg.contains("invalid character"),
            "error must name the offending id and explain why: {msg}"
        );
    }

    #[test]
    fn custom_rule_id_validation_accepts_snake_case() {
        let yaml = r#"
id: my_rule
name: snake-case rule
severity: high
category: authority_propagation
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("snake_case id must be accepted");
        assert_eq!(rule.id, "my_rule");
    }

    #[test]
    fn custom_rule_id_validation_accepts_kebab_case() {
        let yaml = r#"
id: my-rule
name: kebab-case rule
severity: high
category: authority_propagation
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("kebab-case id must be accepted");
        assert_eq!(rule.id, "my-rule");
    }

    #[test]
    fn custom_rule_id_validation_rejects_64_chars_plus_one() {
        let id = "a".repeat(65);
        let yaml = format!("id: {id}\nname: x\nseverity: high\ncategory: authority_propagation\n");
        let err =
            serde_yaml::from_str::<CustomRule>(&yaml).expect_err("65-char id must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("64 characters"),
            "error must cite the 64-char cap: {msg}"
        );

        // 64 chars exactly is fine.
        let id_ok = "a".repeat(64);
        let yaml_ok =
            format!("id: {id_ok}\nname: x\nseverity: high\ncategory: authority_propagation\n");
        let rule: CustomRule =
            serde_yaml::from_str(&yaml_ok).expect("64-char id must be accepted (boundary case)");
        assert_eq!(rule.id.len(), 64);
    }

    #[test]
    fn custom_rule_id_validation_rejects_leading_digit() {
        // Defensive — not in the explicit spec, but documents the
        // first-character rule. Snake_case-friendly + matches the regex.
        let yaml = r#"
id: 1bad
name: x
severity: high
category: authority_propagation
"#;
        let err = serde_yaml::from_str::<CustomRule>(yaml)
            .expect_err("digit-leading id must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("must start"),
            "error must explain the first-char rule: {msg}"
        );
    }
}
