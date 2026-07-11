//! Count and nesting limits imposed by the Logic Apps runtime.
//!
//! Root object counts (parameters, outputs, staticResults), total workflow
//! action count (500), nesting depth (8), operation name length (80 chars),
//! and — because it shares the counting machinery — runAfter status shape.
//! Consumption and Standard differ in the trigger count (Standard is capped
//! at one); the parameter/output caps applied by the root module are the same.

use super::materialized::*;
use super::*;

/// Count entries that survive ARM materialization and flag exceeding `max`.
pub(super) fn validate_root_object_count(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    label: &str,
    max: usize,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let count_and_span = effective_object_entry_count(value, file);
    let Some((count, source_span)) = count_and_span else {
        return;
    };
    if count > max {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer.to_owned(),
            Some(source_span),
            format!("{label} contains {count} entries, but at most {max} are supported"),
        ));
    }
}

/// Enforce the whole-workflow limits: at most 500 actions and 8 levels of
/// nesting. Depth is checked at 9 (index 8 with the surrounding root).
pub(super) fn validate_total_action_limits(
    definition_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let total_actions = workflow.action_list.len();
    if total_actions > 500 {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(definition_pointer, "actions"),
            Some(span(workflow.definition)),
            format!("workflow contains {total_actions} actions, but at most 500 are supported"),
        ));
    }

    for action in &workflow.action_list {
        if action.depth == 9 {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                action.pointer.clone(),
                workflow.node_at(&action.pointer).map(span),
                format!(
                    "action nesting depth is {}, but at most 8 levels are supported",
                    action.depth
                ),
            ));
        }
    }
}

/// Standard workflows allow exactly one trigger; Consumption allows several.
pub(super) fn validate_standard_trigger_count(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !workflow.is_standard() {
        return;
    }
    let count_and_span = effective_object_entry_count(value, file);
    let Some((count, source_span)) = count_and_span else {
        return;
    };
    if count > 1 {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer.to_owned(),
            Some(source_span),
            format!("Standard workflow definitions support only one trigger, but found {count}"),
        ));
    }
}

/// Count the entries in an object under either a spanned or materialized ARM
/// view, ignoring keys ARM has explicitly removed.
pub(super) fn effective_object_entry_count(
    value: &json_spanned_value::spanned::Value,
    file: &JsonFile,
) -> Option<(usize, ByteSpan)> {
    as_object(value)
        .map(|object| {
            (
                object
                    .iter()
                    .filter(|(_, value)| !arm_optional_property_absent(file, value))
                    .count(),
                span(value),
            )
        })
        .or_else(|| {
            static_json_object_from_spanned(file, value).map(|(object, source_span)| {
                (
                    object
                        .values()
                        .filter(|value| !materialized_arm_entry_absent(file, value))
                        .count(),
                    source_span,
                )
            })
        })
}

/// Runtime caps operation names at 80 code points (not bytes) — non-ASCII
/// names are counted by character.
pub(super) fn validate_operation_name_length(
    name: &str,
    operation_pointer: &str,
    label: &str,
    file: &JsonFile,
    source_span: Option<ByteSpan>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if name.chars().count() > 80 {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            operation_pointer.to_owned(),
            source_span,
            format!("{label} name '{name}' exceeds the 80 character limit"),
        ));
    }
}

/// runAfter validation for the materialized-JSON path. `run_after.rs` covers
/// the spanned path; the two are kept in lock-step so ARM-produced runAfter
/// blocks receive the same diagnostics as authored ones.
pub(super) fn validate_json_run_after_statuses(
    run_after: &serde_json::Map<String, serde_json::Value>,
    run_after_pointer: &str,
    file: &JsonFile,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    source_span: ByteSpan,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (dependency, statuses) in run_after {
        let dependency_pointer = pointer_join(run_after_pointer, dependency);
        if materialized_arm_entry_absent(file, statuses)
            || unresolved_arm_array_expression_from_json(file, statuses, arm_scope)
        {
            continue;
        }
        let Some(status_array) = statuses.as_array() else {
            diagnostics.push(Diagnostic::error(
                "runafter-invalid-shape",
                &file.path,
                dependency_pointer,
                Some(source_span),
                "runAfter dependency value must be an array of statuses",
            ));
            continue;
        };
        for (index, status) in status_array.iter().enumerate() {
            let status_pointer = pointer_join(&dependency_pointer, &index.to_string());
            let Some(status_text) = status.as_str() else {
                diagnostics.push(Diagnostic::error(
                    "runafter-invalid-shape",
                    &file.path,
                    status_pointer,
                    Some(source_span),
                    "runAfter status entries must be strings",
                ));
                continue;
            };
            if !run_after_status_supported(status_text) {
                diagnostics.push(Diagnostic::error(
                    "runafter-invalid-status",
                    &file.path,
                    status_pointer,
                    Some(source_span),
                    format!("runAfter status '{status_text}' is not supported"),
                ));
            }
        }
    }
}

/// Enumeration of every runAfter status accepted by the runtime.
/// Case-sensitive — the schema is strict.
pub(super) fn run_after_status_supported(status: &str) -> bool {
    matches!(
        status,
        "Aborted"
            | "Cancelled"
            | "Failed"
            | "Faulted"
            | "Ignored"
            | "Paused"
            | "Running"
            | "Skipped"
            | "Succeeded"
            | "Suspended"
            | "TimedOut"
            | "Waiting"
    )
}
