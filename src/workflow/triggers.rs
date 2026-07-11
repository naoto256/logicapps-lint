//! Record trigger names and the small slice of trigger metadata that other
//! rules key off (type, `splitOn`, `recurrence`, opaque-type flag).
//!
//! No shape validation happens here — this pass answers "does trigger X exist,
//! and is it eligible for check Y?". Same spanned/JSON dual code paths as the
//! rest of the layer, because the whole `triggers` node may itself be an ARM
//! expression that materializes to an object.

use super::arm_support::{
    arm_null_entry_from_json, arm_null_entry_from_spanned, static_object_from_spanned,
    static_string_from_spanned, unresolved_arm_expression_from_json,
    unresolved_arm_expression_from_spanned,
};
use super::*;
use crate::json::{as_object, get};
use json_spanned_value::spanned;

/// Populate all trigger-related fields on `workflow` from a spanned `triggers` map.
pub(super) fn collect_triggers(
    value: Option<&spanned::Value>,
    _pointer: &str,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
    workflow: &mut Workflow<'_>,
) {
    if let Some(object) = value.and_then(as_object) {
        for (name, trigger) in object.iter() {
            if arm_null_entry_from_spanned(trigger, arm_scope) {
                continue;
            }
            workflow.triggers.insert(name.to_string());
            // Three cascading views of the trigger body, coarsest first: the
            // whole thing as one materialized object, individual field lookups
            // on the spanned tree, or — when the type is opaque — record only
            // the flags we can see (splitOn presence still matters).
            if let Some((trigger_object, _source_span)) =
                static_object_from_spanned(trigger, arm_scope)
            {
                if let Some(trigger_type) = trigger_object
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                {
                    workflow
                        .trigger_types
                        .insert(name.to_string(), trigger_type.to_string());
                }
                if trigger_object.contains_key("splitOn") {
                    workflow.triggers_with_split_on.insert(name.to_string());
                }
                if trigger_object.contains_key("recurrence") {
                    workflow.triggers_with_recurrence.insert(name.to_string());
                }
            } else if let Some(trigger_type) =
                get(trigger, "type").and_then(|value| static_string_from_spanned(value, arm_scope))
            {
                workflow
                    .trigger_types
                    .insert(name.to_string(), trigger_type.to_string());
                if get(trigger, "splitOn").is_some() {
                    workflow.triggers_with_split_on.insert(name.to_string());
                }
                if get(trigger, "recurrence").is_some() {
                    workflow.triggers_with_recurrence.insert(name.to_string());
                }
            } else {
                if get(trigger, "type")
                    .is_some_and(|value| unresolved_arm_expression_from_spanned(value, arm_scope))
                {
                    workflow.triggers_with_opaque_type.insert(name.to_string());
                }
                if get(trigger, "splitOn").is_some() {
                    workflow.triggers_with_split_on.insert(name.to_string());
                    if get(trigger, "recurrence").is_some() {
                        workflow.triggers_with_recurrence.insert(name.to_string());
                    }
                }
            }
        }
    } else if let Some((object, _source_span)) =
        value.and_then(|value| static_object_from_spanned(value, arm_scope))
    {
        collect_triggers_json(Some(&serde_json::Value::Object(object)), _pointer, workflow);
    }
}

/// Populate trigger fields from a pre-materialized `serde_json` map. Called
/// when the entire definition or `triggers` node came from an ARM expression.
pub(super) fn collect_triggers_json(
    value: Option<&serde_json::Value>,
    _pointer: &str,
    workflow: &mut Workflow<'_>,
) {
    let Some(object) = value.and_then(serde_json::Value::as_object) else {
        return;
    };
    for (name, trigger) in object {
        if arm_null_entry_from_json(trigger) {
            continue;
        }
        workflow.triggers.insert(name.clone());
        if let Some(type_value) = trigger.get("type") {
            if unresolved_arm_expression_from_json(type_value) {
                workflow.triggers_with_opaque_type.insert(name.clone());
            } else if let Some(trigger_type) = type_value.as_str() {
                workflow
                    .trigger_types
                    .insert(name.clone(), trigger_type.to_string());
            }
        }
        if trigger.get("splitOn").is_some() {
            workflow.triggers_with_split_on.insert(name.clone());
        }
        if trigger.get("recurrence").is_some() {
            workflow.triggers_with_recurrence.insert(name.clone());
        }
    }
}
