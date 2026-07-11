//! ARM deployment-template handling.
//!
//! Three concerns share this module:
//!
//! 1. detecting whether a JSON file is an ARM deployment template at all;
//! 2. surfacing `Microsoft.Logic/workflows` bodies from anywhere in the
//!    template (top-level resources, nested deployments, embedded fixtures)
//!    as [`WorkflowDefinitionCandidate`]s so the workflow-level rules can run;
//! 3. checking the ARM resource shape itself (resource array, copy loops,
//!    nested `scope` semantics, missing workflow parameter values).
//!
//! Static ARM evaluation is deliberately partial: unresolved expressions,
//! `reference()`, and deployment-time inputs stay opaque so downstream checks
//! treat them as unknown rather than empty.
use super::types::{StaticArmValues, WorkflowDefinitionCandidate, WorkflowParameterRequirement};
use crate::diagnostic::Diagnostic;
use crate::json::{
    JsonFile, as_object, as_string, get, pointer_join, span, spanned_from_json, to_json_value,
};

mod definitions;
mod detect;
mod diagnostics;
mod nested;
mod parameters;
mod resources;
mod values;

use definitions::{
    collect_embedded_workflow_definitions, collect_logic_workflow_resource_definitions,
};
use diagnostics::collect_arm_resource_diagnostics;
use resources::has_logic_workflow_resource_in;
use values::static_arm_values;

pub(in crate::check) use detect::is_arm_deployment_template;

/// Every workflow definition in `file`, regardless of container shape.
///
/// Tries shapes in decreasing specificity: Standard `workflow.json` wrapper,
/// bare WDL definition, ARM `Microsoft.Logic/workflows` resources, and
/// finally embedded fixtures. Only reaches the fallback embedded scan when
/// the file is not clearly an ARM template — otherwise a template with no
/// workflow resources correctly returns empty.
pub(in crate::check) fn workflow_definitions(
    file: &JsonFile,
) -> Vec<WorkflowDefinitionCandidate<'_>> {
    let mut candidates = Vec::new();
    let arm_template = is_arm_deployment_template(&file.value);
    // Standard `workflow.json` wraps the WDL body under `definition`.
    if !arm_template && let Some(definition) = get(&file.value, "definition") {
        candidates.push(WorkflowDefinitionCandidate {
            value: definition,
            materialized: None,
            value_is_definition_source: true,
            arm_values: None,
            pointer: "/definition".to_owned(),
            kind: get(&file.value, "kind")
                .and_then(as_string)
                .map(str::to_owned),
            kind_invalid_type: get(&file.value, "kind")
                .filter(|value| as_string(value).is_none())
                .map(|value| ("/kind".to_owned(), span(value))),
        });
        return candidates;
    }

    // Consumption-style definitions and public-schema fixtures can be the WDL
    // definition object itself, without the Standard wrapper.
    if detect::is_workflow_definition(&file.value) || detect::has_workflow_sections(&file.value) {
        candidates.push(WorkflowDefinitionCandidate {
            value: &file.value,
            materialized: None,
            value_is_definition_source: true,
            arm_values: None,
            pointer: String::new(),
            kind: None,
            kind_invalid_type: None,
        });
        return candidates;
    }

    let arm_values = static_arm_values(&file.value);
    let arm_scope = arm_values
        .as_ref()
        .map(StaticArmValues::scope)
        .unwrap_or_default();
    collect_logic_workflow_resource_definitions(&file.value, "", arm_scope, &mut candidates);
    if !candidates.is_empty() || arm_template {
        return candidates;
    }

    collect_embedded_workflow_definitions(&file.value, "", &mut candidates);
    candidates
}

/// Emit ARM-shape diagnostics for the entire template, including nested
/// deployments (with their inherited/overridden parameter scopes).
pub(in crate::check) fn arm_resource_diagnostics(file: &JsonFile) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let arm_values = static_arm_values(&file.value);
    let arm_scope = arm_values
        .as_ref()
        .map(StaticArmValues::scope)
        .unwrap_or_default();
    collect_arm_resource_diagnostics(&file.value, "", arm_scope, file, &mut diagnostics);
    diagnostics
}

/// Cheap probe: does this template contain any Logic workflow resource
/// (including inside nested deployments) that we can prove exists?
pub(in crate::check) fn has_logic_workflow_resource(
    value: &json_spanned_value::spanned::Value,
) -> bool {
    let values = static_arm_values(value).unwrap_or_default();
    has_logic_workflow_resource_in(value, values.scope())
}
