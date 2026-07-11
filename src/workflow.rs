//! Shallow graph summary of a Logic Apps workflow definition.
//!
//! This module flattens the nested `Foreach` / `If` / `Scope` / `Switch` / `Until` /
//! `Agent` container tree into a single index of action names, run-after edges,
//! trigger metadata, parameters, and variable init/mutation sites. Container
//! nesting is deliberately not preserved — rules that need shape context re-read
//! the original spanned JSON via [`Workflow::node_at`]. Think of `Workflow` as a
//! capability lookup, not the ground truth.
//!
//! ARM-embedded definitions add a second wrinkle: individual leaf strings (or
//! whole subtrees) may be opaque `[...]` expressions that only resolve at
//! deployment. Fields ending in `has_opaque_*` mark such holes so downstream
//! rules do not falsely flag "missing" values; helpers in
//! [`arm_support`](arm_support) draw the static-vs-opaque boundary.

use json_spanned_value::spanned;
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};

mod actions;
mod arm_support;
mod extraction;
mod parameters;
mod run_after;
mod strings;
mod triggers;
mod variables;

pub use run_after::run_after_refs;
pub use strings::{string_sites, string_sites_with_arm_static};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Standard workflow wrapper kind, as seen at extraction time.
pub enum WorkflowKind {
    /// The wrapper `kind` field was a string with this value.
    Named(String),
    /// The wrapper `kind` field was present but not a string.
    ///
    /// The invalid-type shape diagnostic is emitted separately; downstream rules
    /// still treat the file as a Standard wrapper so that Standard-only checks
    /// remain in scope.
    InvalidType,
}

impl WorkflowKind {
    /// The wrapper `kind` value when it was a plain string, otherwise `None`.
    pub fn as_named(&self) -> Option<&str> {
        match self {
            Self::Named(name) => Some(name.as_str()),
            Self::InvalidType => None,
        }
    }
}

#[derive(Debug)]
/// Workflow graph summary used by shape and reference rules.
pub struct Workflow<'a> {
    /// Root workflow definition value.
    pub definition: &'a spanned::Value,
    /// JSON Pointer to `definition`, empty for standalone definitions.
    pub definition_pointer: String,
    /// Standard workflow wrapper kind, when the definition came from `workflow.json`.
    pub kind: Option<WorkflowKind>,
    /// First action seen for each globally unique action name.
    pub actions: BTreeMap<String, ActionInfo>,
    /// All actions, including duplicates, in traversal order.
    pub action_list: Vec<ActionInfo>,
    /// Duplicate action declarations that cannot safely be collapsed into `actions`.
    pub duplicate_actions: Vec<DuplicateAction>,
    /// Trigger names declared by the workflow.
    pub triggers: BTreeSet<String>,
    /// Trigger type by name when statically visible.
    pub trigger_types: BTreeMap<String, String>,
    /// Triggers whose type is an unresolved ARM expression.
    pub triggers_with_opaque_type: BTreeSet<String>,
    /// Triggers that statically declare `splitOn`.
    pub triggers_with_split_on: BTreeSet<String>,
    /// Triggers that statically declare `recurrence`.
    pub triggers_with_recurrence: BTreeSet<String>,
    /// Parameters declared inside the workflow definition.
    pub parameters: BTreeSet<String>,
}

#[derive(Debug, Clone)]
/// Action metadata flattened out of nested Logic Apps containers.
pub struct ActionInfo {
    /// Action name as declared under its containing `actions` object.
    pub name: String,
    /// JSON Pointer to the action object.
    pub pointer: String,
    /// JSON Pointer to the containing `actions` object.
    pub container_pointer: String,
    /// Nesting depth, with root workflow actions at depth 1.
    pub depth: usize,
    /// Statically visible action type, including type materialized from ARM expressions.
    pub action_type: Option<String>,
    /// Action type is an unresolved ARM expression and must not be treated as absent.
    pub has_opaque_type: bool,
    /// Coarse action class used by reference scoping rules.
    pub kind: ActionKind,
    /// `runAfter` dependencies materialized from raw JSON or static ARM expressions.
    pub run_after: Vec<RunAfterDependency>,
    /// `runAfter` is an unresolved ARM expression and may provide dependencies at deployment time.
    pub has_opaque_run_after: bool,
    /// Variables initialized by this action, materialized from raw JSON or static ARM expressions.
    pub initialized_variables: Vec<InitializedVariable>,
    /// Variable target name for mutation actions such as `SetVariable`.
    pub variable_target: Option<VariableTarget>,
    /// String values assigned by `SetVariable`, if statically visible.
    pub variable_value: Option<VariableValue>,
}

#[derive(Debug, Clone)]
/// Target variable of a mutation action (`SetVariable`, `AppendTo*Variable`,
/// `Increment/DecrementVariable`), located for reference rules.
pub struct VariableTarget {
    /// Name from `inputs.name`; may or may not resolve to an initialized variable.
    pub name: String,
    /// JSON Pointer to the `inputs.name` node.
    pub pointer: String,
    /// Source span of the name literal, for diagnostic anchoring.
    pub span: crate::diagnostic::ByteSpan,
}

#[derive(Debug, Clone)]
/// Variable declared by an `InitializeVariable` action's `inputs`.
pub struct InitializedVariable {
    /// Variable name as declared in `inputs.name` (or per-entry `name`).
    pub name: String,
    /// Declared type; case is preserved from source and validated against
    /// [`is_variable_type`](self::variables) elsewhere.
    pub variable_type: String,
}

#[derive(Debug, Clone)]
/// String values assigned by `SetVariable`, flattened from `inputs.value`.
///
/// A single scalar becomes one entry; nested objects/arrays are walked and each
/// string leaf is captured so downstream rules can check every literal against
/// the declared variable type.
pub struct VariableValue {
    /// All string leaves reached under `inputs.value`, in traversal order.
    pub values: Vec<String>,
    /// JSON Pointer to `inputs.value`.
    pub pointer: String,
    /// Source span of the `inputs.value` node.
    pub span: crate::diagnostic::ByteSpan,
}

#[derive(Debug, Clone)]
/// Single edge in an action's `runAfter` map.
///
/// One `RunAfterDependency` corresponds to one predecessor action name — the
/// map from raw JSON is expanded into a `Vec` so each edge carries its own
/// pointer/span for diagnostic anchoring.
pub struct RunAfterDependency {
    /// Predecessor action name (map key under `runAfter`).
    pub dependency: String,
    /// JSON Pointer to the per-dependency entry.
    pub pointer: String,
    /// Source span for the entry; falls back to the parent span when the
    /// dependency was materialized from a static ARM expression.
    pub span: crate::diagnostic::ByteSpan,
    /// Trigger statuses declared for the edge (`Succeeded`, `Failed`, ...);
    /// empty when the runtime default should apply.
    pub statuses: Vec<String>,
}

#[derive(Debug, Clone)]
/// Duplicate action declaration with enough data to report the later entry.
pub struct DuplicateAction {
    /// Duplicate action name.
    pub name: String,
    /// JSON Pointer to the duplicate entry.
    pub pointer: String,
    /// JSON Pointer to the first action with the same name.
    pub first_pointer: String,
    /// Source span of the duplicate action object.
    pub span: crate::diagnostic::ByteSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Coarse action behavior relevant to WDL helper scoping.
pub enum ActionKind {
    /// `Foreach` container; supports `items('name')` and current `item()`.
    Foreach,
    /// `If` container; may execute actions under `actions` and `else.actions`.
    If,
    /// `Scope` container; supports `result('name')`.
    Scope,
    /// `Switch` container; may execute actions under cases and default.
    Switch,
    /// `Until` container; supports `result('name')` and `iterationIndexes('name')`.
    Until,
    /// Agent container; may execute tool actions.
    Agent,
    /// Per-item data operation such as Query, Select, or Table.
    DataOperation,
    /// Any action kind without special WDL reference scoping.
    Other,
}

impl ActionKind {
    /// Classify a raw action type string. `None` and unknown types collapse to
    /// [`Self::Other`] — the graph only encodes the container/reference shapes
    /// that WDL scoping cares about, not the full public schema.
    pub fn from_action_type(action_type: Option<&str>) -> Self {
        // Action type matching is case-insensitive here because the graph is a
        // capability model for WDL scoping, not the public-schema enum check.
        match action_type {
            Some(action_type) if action_type.eq_ignore_ascii_case("foreach") => Self::Foreach,
            Some(action_type) if action_type.eq_ignore_ascii_case("if") => Self::If,
            Some(action_type) if action_type.eq_ignore_ascii_case("scope") => Self::Scope,
            Some(action_type) if action_type.eq_ignore_ascii_case("switch") => Self::Switch,
            Some(action_type) if action_type.eq_ignore_ascii_case("until") => Self::Until,
            Some(action_type) if action_type.eq_ignore_ascii_case("agent") => Self::Agent,
            Some(action_type)
                if action_type.eq_ignore_ascii_case("query")
                    || action_type.eq_ignore_ascii_case("select")
                    || action_type.eq_ignore_ascii_case("table") =>
            {
                Self::DataOperation
            }
            _ => Self::Other,
        }
    }

    /// Whether nested child actions may appear under a plain `actions` field.
    /// `Switch` is excluded — its children live under `cases`/`default`; `Agent`
    /// is excluded — its children live under `tools`.
    pub fn supports_actions_container(self) -> bool {
        matches!(self, Self::Foreach | Self::If | Self::Scope | Self::Until)
    }

    /// Whether child actions may appear under `cases.<name>.actions`.
    pub fn supports_cases_container(self) -> bool {
        matches!(self, Self::Switch)
    }

    /// Whether child actions may appear under `default.actions`.
    pub fn supports_default_container(self) -> bool {
        matches!(self, Self::Switch)
    }

    /// Whether child actions may appear under `else.actions`.
    pub fn supports_else_container(self) -> bool {
        matches!(self, Self::If)
    }

    /// Whether child actions may appear under `tools.<name>.actions`
    /// (Agent container hosts tool workflows as siblings).
    pub fn supports_tools_container(self) -> bool {
        matches!(self, Self::Agent)
    }

    /// Whether `items('<name>')` may target this action.
    pub fn supports_items(self) -> bool {
        matches!(self, Self::Foreach)
    }

    /// Whether `item()` can be valid somewhere under this action.
    ///
    /// Data operations still need field-level refinement in the reference rule.
    pub fn supports_current_item(self) -> bool {
        matches!(self, Self::Foreach | Self::DataOperation)
    }

    /// Whether `result('<name>')` may target this action.
    pub fn supports_result(self) -> bool {
        matches!(self, Self::Foreach | Self::Scope | Self::Until)
    }
}

#[derive(Debug, Clone)]
/// One string leaf encountered while walking a value tree.
///
/// Sites come from two origins: literal JSON strings in the source, and
/// synthetic fragments materialized from ARM `[...]` expressions when a
/// scope is provided. The `arm_*` flags let downstream rules distinguish
/// them and decide how strictly to interpret partial matches.
pub struct StringSite<'a> {
    /// The string content. `Borrowed` for raw JSON strings, `Owned` when
    /// materialized from an ARM expression evaluation.
    pub value: Cow<'a, str>,
    /// JSON Pointer to the leaf.
    pub pointer: String,
    /// Source span of the enclosing JSON value.
    pub span: crate::diagnostic::ByteSpan,
    /// Site was produced by evaluating an ARM expression statically.
    pub arm_static: bool,
    /// Site is only a partial fragment of a larger ARM expression — matches
    /// need to allow characters on either flagged side.
    pub arm_partial: bool,
    /// Fragment could have unseen prefix content (an ARM subexpression).
    pub arm_partial_can_extend_left: bool,
    /// Fragment could have unseen suffix content (an ARM subexpression).
    pub arm_partial_can_extend_right: bool,
}

#[derive(Debug, Clone)]
/// Flat, per-edge view of the run-after graph produced by [`run_after_refs`].
///
/// One instance per `(action, dependency)` pair — cycles and unknown references
/// are validated by rules, not filtered here.
pub struct RunAfterRef {
    /// The action holding the `runAfter` clause.
    pub action: String,
    /// The named predecessor.
    pub dependency: String,
    /// Pointer to the enclosing actions container (`action`'s parent).
    pub container_pointer: String,
    /// Pointer to the individual `runAfter/<dependency>` entry.
    pub pointer: String,
    /// Span for diagnostic anchoring.
    pub span: crate::diagnostic::ByteSpan,
}

/// Extract a workflow summary without ARM-scope resolution.
///
/// Use this when the definition stands alone (Standard `workflow.json`) or when
/// no ARM parameter values are known. Opaque `[...]` fields are treated purely
/// as strings — the `has_opaque_*` flags stay `false` because there is no
/// scope in which to try to resolve them.
pub fn extract_definition<'a>(
    definition: &'a spanned::Value,
    definition_pointer: &str,
    kind: Option<WorkflowKind>,
) -> Workflow<'a> {
    extraction::extract_definition_inner(definition, definition_pointer, kind, None)
}

/// Extract a workflow summary with an ARM static scope for expression evaluation.
///
/// Passing a scope enables two things at once: statically-resolvable ARM
/// expressions are materialized into concrete strings/objects, and unresolved
/// expressions are recognized as such and marked via `has_opaque_*` so
/// downstream rules skip false-positive "missing" reports.
pub fn extract_definition_with_arm_scope<'a>(
    definition: &'a spanned::Value,
    definition_pointer: &str,
    kind: Option<WorkflowKind>,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> Workflow<'a> {
    extraction::extract_definition_inner(definition, definition_pointer, kind, Some(arm_scope))
}

impl<'a> Workflow<'a> {
    /// Resolve a pointer stored on the summary back into the original spanned
    /// tree. Pointers are stored with the `definition_pointer` prefix for
    /// diagnostic output; here we strip it before descending.
    pub fn node_at(&self, pointer: &str) -> Option<&'a spanned::Value> {
        let relative = arm_support::strip_prefix_pointer(pointer, &self.definition_pointer);
        self.definition.pointer(relative)
    }

    /// True when the wrapper `kind` string was `Stateless`. Case-insensitive
    /// because the runtime accepts both `Stateful` and `stateful` etc.
    pub fn is_stateless(&self) -> bool {
        self.kind
            .as_ref()
            .and_then(WorkflowKind::as_named)
            .is_some_and(|kind| kind.eq_ignore_ascii_case("Stateless"))
    }

    /// True when the definition came from a Standard `workflow.json` (i.e. any
    /// wrapper kind was recorded, valid or not). Consumption definitions have
    /// no wrapper `kind` and return `false`.
    pub fn is_standard(&self) -> bool {
        self.kind.is_some()
    }

    /// Whether this definition belongs to a Consumption ARM workflow resource.
    pub fn is_embedded_arm_definition(&self) -> bool {
        self.definition_pointer.ends_with("/properties/definition")
    }
}
