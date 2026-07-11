//! Shape detection for the various ARM/WDL JSON payloads we might be handed.
//!
//! The functions here are intentionally schema-URL-first (authoritative when
//! present) with structural heuristics as fall-back — many fixtures ship
//! without `$schema` at all.
use super::*;

/// True when the payload's `$schema` names a Logic workflow definition schema.
pub(super) fn is_workflow_definition(value: &json_spanned_value::spanned::Value) -> bool {
    get(value, "$schema")
        .and_then(as_string)
        .is_some_and(|schema| {
            schema.contains("/providers/Microsoft.Logic/schemas/")
                && schema.contains("/workflowdefinition.json")
        })
}

/// Matches the ARM location `.../properties/definition` where a workflow body
/// is embedded — the JSON pointer suffix is what disambiguates a real Logic
/// definition from arbitrary payloads that happen to use `actions`/`triggers`.
pub(super) fn is_embedded_workflow_definition(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
) -> bool {
    pointer.ends_with("/properties/definition") && has_workflow_sections(value)
}

/// Structural signature of a WDL body — either `actions` or `triggers`.
pub(super) fn has_workflow_sections(value: &json_spanned_value::spanned::Value) -> bool {
    get(value, "actions").is_some() || get(value, "triggers").is_some()
}

/// Whether the top-level document is an ARM deployment template.
///
/// Order matters: an explicit `$schema` (either deployment or workflow) is
/// decisive; only in its absence do we fall back to the structural
/// "has `resources`, does not look like a definition" heuristic.
pub(in crate::check) fn is_arm_deployment_template(
    value: &json_spanned_value::spanned::Value,
) -> bool {
    let schema = get(value, "$schema").and_then(as_string);
    if schema.is_some_and(|schema| schema.contains("/deploymentTemplate.json")) {
        return true;
    }
    if schema.is_some_and(|schema| schema.contains("/workflowdefinition.json")) {
        return false;
    }
    !has_workflow_sections(value)
        && get(value, "definition").is_none()
        && get(value, "resources").is_some_and(arm_template_resources_present)
}

/// Only counts as "has resources" when the value is not literally null and,
/// when authored as an ARM expression, does not statically evaluate to null.
/// Prevents an empty ARM stub from being classified as a deployment template.
pub(super) fn arm_template_resources_present(
    resources: &json_spanned_value::spanned::Value,
) -> bool {
    if resources.is_null() {
        return false;
    }
    if let Some(text) = as_string(resources)
        && crate::arm::is_full_expression(text)
        && crate::arm::static_expression_value(text).is_some_and(|value| value.is_null())
    {
        return false;
    }
    true
}
