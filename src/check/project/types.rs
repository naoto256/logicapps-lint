//! Shared project-layer types.
//!
//! These types describe what was *found* in the project (ARM values, workflow
//! definition candidates, connection reference sites) without yet judging
//! whether it is correct — the rule modules do that.

use crate::diagnostic::{ByteSpan, Diagnostic};
use crate::json::JsonFile;

/// Statically-resolvable ARM template values reachable from a scope.
///
/// Carries the subset of `parameters` / `variables` / `functions` that we can
/// evaluate without runtime deployment context. Anything dynamic (unresolved
/// expressions, `reference()`, deployment-time inputs) is deliberately absent
/// so downstream checks treat it as unknown rather than empty.
#[derive(Clone, Default)]
pub(in crate::check) struct StaticArmValues {
    pub(in crate::check) variables: crate::arm::ArmValues,
    pub(in crate::check) parameters: crate::arm::ArmValues,
    pub(in crate::check) parameter_types: crate::arm::ArmValues,
    pub(in crate::check) functions: crate::arm::ArmFunctions,
}

impl StaticArmValues {
    pub(in crate::check) fn is_empty(&self) -> bool {
        self.variables.is_empty()
            && self.parameters.is_empty()
            && self.parameter_types.is_empty()
            && self.functions.is_empty()
    }

    pub(in crate::check) fn scope(&self) -> crate::arm::ArmStaticScope<'_> {
        crate::arm::ArmStaticScope {
            variables: Some(&self.variables),
            parameters: Some(&self.parameters),
            parameter_types: Some(&self.parameter_types),
            functions: Some(&self.functions),
            copy_index: None,
        }
    }

    pub(in crate::check) fn from_scope(scope: crate::arm::ArmStaticScope<'_>) -> Option<Self> {
        let values = Self {
            variables: scope.variables.cloned().unwrap_or_default(),
            parameters: scope.parameters.cloned().unwrap_or_default(),
            parameter_types: scope.parameter_types.cloned().unwrap_or_default(),
            functions: scope.functions.cloned().unwrap_or_default(),
        };
        (!values.is_empty()).then_some(values)
    }
}

/// A workflow definition located inside some file, pre-extraction.
///
/// A candidate may originate from a Standard `workflow.json` wrapper, an
/// ARM-embedded `Microsoft.Logic/workflows` resource, or a template workflow
/// body. When the ARM definition contained expressions we could evaluate,
/// `materialized` holds the resolved copy while `value` still points at the
/// original spans — diagnostics keep pointing at authored bytes even though
/// the checks read the resolved shape.
pub(in crate::check) struct WorkflowDefinitionCandidate<'a> {
    /// Original authored value; preserves spans for diagnostics.
    pub(in crate::check) value: &'a json_spanned_value::spanned::Value,
    /// Copy with static ARM expressions resolved, when we could produce one.
    pub(in crate::check) materialized: Option<json_spanned_value::spanned::Value>,
    /// True when `value` itself is the definition body; false when it points
    /// at the surrounding ARM resource so diagnostics can attach there while
    /// checks read `materialized`.
    pub(in crate::check) value_is_definition_source: bool,
    /// ARM scope in effect at the definition site (parent/nested inheritance already applied).
    pub(in crate::check) arm_values: Option<StaticArmValues>,
    /// JSON Pointer from the file root to the definition.
    pub(in crate::check) pointer: String,
    /// Workflow kind (e.g. "Stateful"), when authored as a string.
    pub(in crate::check) kind: Option<String>,
    /// Present when `kind` was authored but not a string — recorded so the
    /// wrapper diagnostic can attach at the correct span even though the
    /// value is unusable for downstream logic.
    pub(super) kind_invalid_type: Option<(String, ByteSpan)>,
}

impl<'a> WorkflowDefinitionCandidate<'a> {
    pub(in crate::check) fn effective_value(&self) -> &json_spanned_value::spanned::Value {
        self.materialized.as_ref().unwrap_or(self.value)
    }

    pub(in crate::check) fn reference_value(&self) -> &json_spanned_value::spanned::Value {
        if self.value_is_definition_source {
            self.value
        } else {
            self.effective_value()
        }
    }

    pub(in crate::check) fn effective_kind(&self) -> Option<crate::workflow::WorkflowKind> {
        if self.kind_invalid_type.is_some() {
            Some(crate::workflow::WorkflowKind::InvalidType)
        } else {
            self.kind.clone().map(crate::workflow::WorkflowKind::Named)
        }
    }

    pub(in crate::check) fn arm_scope(&self) -> crate::arm::ArmStaticScope<'_> {
        self.arm_values
            .as_ref()
            .map(StaticArmValues::scope)
            .unwrap_or_default()
    }

    pub(in crate::check) fn kind_invalid_type_diagnostic(
        &self,
        file: &JsonFile,
    ) -> Option<Diagnostic> {
        let (pointer, span) = self.kind_invalid_type.as_ref()?;
        Some(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer.clone(),
            Some(*span),
            "workflow kind must be a string",
        ))
    }
}

/// A single connection-reference site inside a workflow definition.
///
/// `name` is `None` when the reference field was present but not a string —
/// the site still surfaces so a type diagnostic can be raised.
pub(super) struct ConnectionReferenceSite {
    pub(super) name: Option<String>,
    pub(super) kind: ConnectionReferenceKind,
    pub(super) pointer: String,
    pub(super) span: crate::diagnostic::ByteSpan,
}

/// Which `connections.json` section a reference must resolve against.
///
/// `Template` is a synthetic bucket for consumption-template
/// `parameters('$connections')` references, which are validated against the
/// manifest instead of a real `connections.json` section.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ConnectionReferenceKind {
    ManagedApi,
    ServiceProvider,
    Function,
    Template,
}

/// A definition parameter and whether it needs a matching value.
///
/// `requires_value` is false for `$connections` and for parameters that carry
/// a `defaultValue` — those cases can be silently satisfied.
pub(super) struct WorkflowParameterRequirement {
    pub(super) name: String,
    pub(super) pointer: String,
    pub(super) span: ByteSpan,
    pub(super) requires_value: bool,
}
