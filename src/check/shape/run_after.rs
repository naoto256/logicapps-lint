//! `runAfter` shape check for the spanned (authored) view.
//!
//! `runAfter` maps a dependency action name to an array of status strings.
//! Each status must match the Logic Apps status enum exactly (case-sensitive).
//! The materialized-JSON counterpart lives in `limits.rs`; both agree on the
//! same enum so ARM-produced runAfter blocks receive identical diagnostics.

use super::materialized::{
    arm_optional_property_absent, unresolved_arm_array_expression_from_spanned,
};
use super::*;

/// Validate each dependency's status array. Missing or opaque-ARM entries pass
/// through untouched; wrong-type entries are flagged as `runafter-invalid-shape`.
pub(super) fn validate_run_after_statuses(
    run_after: &json_spanned_value::Map<
        json_spanned_value::spanned::String,
        json_spanned_value::spanned::Value,
    >,
    run_after_pointer: &str,
    file: &JsonFile,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (dependency, statuses) in run_after.iter() {
        let dependency_pointer = pointer_join(run_after_pointer, dependency);
        if arm_optional_property_absent(file, statuses)
            || unresolved_arm_array_expression_from_spanned(file, statuses, arm_scope)
        {
            continue;
        }
        let Some(status_array) = statuses.as_span_array() else {
            diagnostics.push(Diagnostic::error(
                "runafter-invalid-shape",
                &file.path,
                dependency_pointer,
                Some(span(statuses)),
                "runAfter dependency value must be an array of statuses",
            ));
            continue;
        };
        for (index, status) in status_array.iter().enumerate() {
            let status_pointer = pointer_join(&dependency_pointer, &index.to_string());
            let Some(status_text) = as_string(status) else {
                diagnostics.push(Diagnostic::error(
                    "runafter-invalid-shape",
                    &file.path,
                    status_pointer,
                    Some(span(status)),
                    "runAfter status entries must be strings",
                ));
                continue;
            };
            if !matches!(
                status_text,
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
            ) {
                diagnostics.push(Diagnostic::error(
                    "runafter-invalid-status",
                    &file.path,
                    status_pointer,
                    Some(span(status)),
                    format!("runAfter status '{status_text}' is not supported"),
                ));
            }
        }
    }
}
