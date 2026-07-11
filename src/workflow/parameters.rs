//! Collect the set of `parameters` declared inside a workflow definition.
//!
//! Only names matter here — types and default values are validated by shape
//! rules against the raw JSON. Handles the `union(...)`-materialized case
//! where the entire `parameters` object came from an ARM expression.

use super::arm_support::{arm_null_entry_from_json, arm_null_entry_from_spanned};
use crate::json::{as_object, as_string};
use json_spanned_value::spanned;
use std::collections::BTreeSet;

/// Collect parameter names from spanned JSON, with ARM opt-out handling.
pub(super) fn collect_parameters(
    value: Option<&spanned::Value>,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
    out: &mut BTreeSet<String>,
) {
    if let Some(object) = value.and_then(as_object) {
        for (key, value) in object.iter() {
            if arm_null_entry_from_spanned(value, arm_scope) {
                continue;
            }
            out.insert(key.to_string());
        }
    // Fallback: the `parameters` node might be a single string that is an ARM
    // expression composing an object (`union(...)` etc.). Pull out entry names
    // even when the full expression cannot be fully evaluated.
    } else if let Some(text) = value.and_then(as_string)
        && let Some(arm_scope) = arm_scope
        && let Some(entries) =
            crate::arm::static_expression_object_entries_with_scope(text, arm_scope)
    {
        out.extend(
            entries
                .into_iter()
                .filter(|(_, value)| !arm_null_entry_from_json(value))
                .map(|(key, _)| key),
        );
    }
}

/// Collect parameter names from a pre-materialized `serde_json` object.
/// Used when the definition itself came out of an ARM expression.
pub(super) fn collect_parameters_json(
    value: Option<&serde_json::Value>,
    out: &mut BTreeSet<String>,
) {
    let Some(object) = value.and_then(serde_json::Value::as_object) else {
        return;
    };
    out.extend(
        object
            .iter()
            .filter(|(_, value)| !arm_null_entry_from_json(value))
            .map(|(key, _)| key.clone()),
    );
}
