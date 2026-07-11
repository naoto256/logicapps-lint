//! Extract `runAfter` edges from action bodies.
//!
//! Each `runAfter` is a map `{ predecessorName: [statusStrings] }`. We fan it
//! out into one [`RunAfterDependency`] per key so each edge carries its own
//! pointer and span for diagnostics. ARM handling mirrors the rest of the
//! layer: opt-out nulls, static materialization, and an opaque-hole flag
//! (`has_opaque_run_after`) when we cannot see the map at all.

use super::arm_support::{
    arm_null_entry_from_json, arm_null_entry_from_spanned, static_object_from_spanned,
    unresolved_arm_expression_from_json, unresolved_arm_expression_from_spanned,
};
use super::*;
use crate::json::{as_object, as_string, get, pointer_join, span};
use json_spanned_value::spanned;

/// Flatten every action's `runAfter` map into a single edge list.
///
/// Preserves duplicates and traversal order — cycle detection, unknown-target
/// validation, and status-vocabulary checks all belong to individual rules.
pub fn run_after_refs(workflow: &Workflow<'_>) -> Vec<RunAfterRef> {
    let mut refs = Vec::new();
    for action in &workflow.action_list {
        for dependency in &action.run_after {
            refs.push(RunAfterRef {
                action: action.name.clone(),
                dependency: dependency.dependency.clone(),
                container_pointer: action.container_pointer.clone(),
                pointer: dependency.pointer.clone(),
                span: dependency.span,
            });
        }
    }
    refs
}

/// Read edges from spanned JSON, falling back through ARM materialization steps.
pub(super) fn run_after_dependencies_from_spanned(
    value: &spanned::Value,
    action_pointer: &str,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> Vec<RunAfterDependency> {
    let Some(run_after) = get(value, "runAfter") else {
        return Vec::new();
    };
    if arm_null_entry_from_spanned(run_after, arm_scope) {
        return Vec::new();
    }
    let run_after_pointer = pointer_join(action_pointer, "runAfter");
    if let Some(object) = as_object(run_after) {
        return object
            .iter()
            .filter(|(_, value)| !arm_null_entry_from_spanned(value, arm_scope))
            .map(|(dependency, value)| RunAfterDependency {
                dependency: dependency.to_string(),
                pointer: pointer_join(&run_after_pointer, dependency),
                span: span(value),
                statuses: run_after_statuses_from_spanned(value),
            })
            .collect();
    }
    // Not a live map, so it must be an ARM expression. Try full evaluation
    // first; if that fails, fall back to entry-level extraction so we can
    // still see individual dependency names from `union(...)`-shaped exprs.
    let Some((object, source_span)) = static_object_from_spanned(run_after, arm_scope) else {
        return partial_static_run_after_dependencies_from_spanned(
            run_after,
            &run_after_pointer,
            arm_scope,
        );
    };
    object
        .iter()
        .filter(|(_, value)| !arm_null_entry_from_json(value))
        .map(|(dependency, value)| RunAfterDependency {
            dependency: dependency.to_string(),
            pointer: pointer_join(&run_after_pointer, dependency),
            span: source_span,
            statuses: run_after_statuses_from_json(value),
        })
        .collect()
}

/// Recover dependency names from a partially-static ARM expression whose full
/// value we cannot compute but whose entry keys we can enumerate.
pub(super) fn partial_static_run_after_dependencies_from_spanned(
    value: &spanned::Value,
    run_after_pointer: &str,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> Vec<RunAfterDependency> {
    let Some(arm_scope) = arm_scope else {
        return Vec::new();
    };
    let Some(text) = as_string(value) else {
        return Vec::new();
    };
    let Some(entries) = crate::arm::static_expression_object_entries_with_scope(text, arm_scope)
    else {
        return Vec::new();
    };
    entries
        .into_iter()
        .filter(|(_, entry_value)| !arm_null_entry_from_json(entry_value))
        .map(|(dependency, entry_value)| RunAfterDependency {
            pointer: pointer_join(run_after_pointer, &dependency),
            dependency,
            span: span(value),
            statuses: run_after_statuses_from_json(&entry_value),
        })
        .collect()
}

/// True when `runAfter` is present but is an opaque ARM expression — signals
/// downstream rules that the action may have dependencies invisible here.
pub(super) fn has_opaque_run_after_from_spanned(
    value: &spanned::Value,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> bool {
    let Some(run_after) = get(value, "runAfter") else {
        return false;
    };
    unresolved_arm_expression_from_spanned(run_after, arm_scope)
}

/// Serde-json variant used when the enclosing action was itself materialized
/// from ARM; all edges share `source_span` because per-key spans are gone.
pub(super) fn run_after_dependencies_from_json(
    value: &serde_json::Value,
    action_pointer: &str,
    source_span: crate::diagnostic::ByteSpan,
) -> Vec<RunAfterDependency> {
    let Some(object) = value.get("runAfter").and_then(serde_json::Value::as_object) else {
        return Vec::new();
    };
    let run_after_pointer = pointer_join(action_pointer, "runAfter");
    object
        .keys()
        .map(|dependency| RunAfterDependency {
            dependency: dependency.to_string(),
            pointer: pointer_join(&run_after_pointer, dependency),
            span: source_span,
            statuses: run_after_statuses_from_json(
                object.get(dependency).unwrap_or(&serde_json::Value::Null),
            ),
        })
        .collect()
}

/// Serde-json variant of the opaque-check for post-materialized values.
pub(super) fn has_opaque_run_after_from_json(value: &serde_json::Value) -> bool {
    let Some(run_after) = value.get("runAfter") else {
        return false;
    };
    unresolved_arm_expression_from_json(run_after)
}

fn run_after_statuses_from_spanned(value: &spanned::Value) -> Vec<String> {
    value
        .as_span_array()
        .into_iter()
        .flat_map(|values| values.iter())
        .filter_map(as_string)
        .map(ToOwned::to_owned)
        .collect()
}

fn run_after_statuses_from_json(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flat_map(|values| values.iter())
        .filter_map(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}
