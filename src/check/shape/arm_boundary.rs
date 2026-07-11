//! Seam between static workflow checks and opaque ARM expressions.
//!
//! Every shape rule that inspects a scalar first asks whether the value could
//! be a full ARM expression (`"[...]"`) that we cannot evaluate. When it can,
//! the rule skips its static check and defers to the materialized pass in
//! `materialized.rs`. Whether ARM expressions are allowed at all depends on
//! the source schema — this module encapsulates that decision.

use super::*;

/// True when `value` is a fully opaque ARM expression in a file where ARM
/// expressions are legal. Callers use this to bail out of static checks.
pub(super) fn is_opaque_arm_expression(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
) -> bool {
    file_allows_arm_expressions(file) && as_string(value).is_some_and(is_arm_full_expression)
}

/// Whether the enclosing file is an ARM template (or an unlabeled document that
/// still looks like one). Workflow-definition files never permit ARM expressions;
/// deploymentTemplate files always do; anything else is inferred from shape.
pub(super) fn file_allows_arm_expressions(file: &JsonFile) -> bool {
    let schema = get(&file.value, "$schema").and_then(as_string);
    if schema.is_some_and(|schema| schema.contains("/deploymentTemplate.json")) {
        return true;
    }
    if schema.is_some_and(|schema| schema.contains("/workflowdefinition.json")) {
        return false;
    }
    // Unlabeled document: only treat it as ARM when there is no workflow root,
    // no `definition`, and a non-null `resources` array to anchor the template.
    !has_root_workflow_sections(&file.value)
        && get(&file.value, "definition").is_none()
        && get(&file.value, "resources").is_some_and(resources_property_allows_arm_expressions)
}

fn has_root_workflow_sections(value: &json_spanned_value::spanned::Value) -> bool {
    get(value, "actions").is_some() || get(value, "triggers").is_some()
}

fn resources_property_allows_arm_expressions(value: &json_spanned_value::spanned::Value) -> bool {
    if value.is_null() {
        return false;
    }
    // A `resources` written as an ARM expression that statically resolves to
    // null should not enable ARM handling — that document is effectively empty.
    if let Some(text) = as_string(value)
        && crate::arm::is_full_expression(text)
        && crate::arm::static_expression_value(text).is_some_and(|value| value.is_null())
    {
        return false;
    }
    true
}

/// Thin re-export so callers stay off `crate::arm` for the common predicate.
pub(super) fn is_arm_full_expression(text: &str) -> bool {
    crate::arm::is_full_expression(text)
}
