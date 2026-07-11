//! ARM-driven resolution of `parameters('x')` names.
//!
//! In an ARM deployment template the workflow's `definition.parameters` object
//! may be:
//!   * literal JSON — parameters visible in the WDL layer as usual,
//!   * a static ARM expression with a known object shape — visible names come
//!     from its keys,
//!   * a fully dynamic ARM expression — the parameter set is only known at
//!     deploy time and every `parameters(...)` reference must be tolerated.

use crate::json::{as_string, get};
use crate::workflow::Workflow;
use std::collections::BTreeSet;

/// True when `definition.parameters` is an ARM expression whose value cannot
/// be resolved statically, so the WDL layer cannot enumerate parameter names.
pub(super) fn workflow_definition_parameters_dynamic(workflow: &Workflow<'_>) -> bool {
    get(workflow.definition, "parameters")
        .and_then(as_string)
        .is_some_and(|text| {
            // Only ARM expressions can be dynamic; a literal JSON object is
            // handled by the normal WDL parameter set.
            if !crate::arm::is_full_expression(text) {
                return false;
            }
            // A static ARM expression whose keys are known is not dynamic.
            if crate::arm::static_expression_object_keys(text).is_some() {
                return false;
            }
            // A fully evaluable ARM expression is also not dynamic — its
            // resolved value can be reasoned about as JSON.
            crate::arm::static_expression_value(text).is_none()
        })
}

/// Parameter names that a static ARM expression is known to expose as keys.
/// Used to accept `parameters('x')` even though the ARM object never appears
/// as literal JSON in the workflow definition.
pub(super) fn workflow_definition_static_parameters(workflow: &Workflow<'_>) -> BTreeSet<String> {
    get(workflow.definition, "parameters")
        .and_then(as_string)
        .and_then(crate::arm::static_expression_object_keys)
        .unwrap_or_default()
}
