//! `staticResults` declarations and their per-action bindings.
//!
//! A workflow can pre-declare mock results under `definition.staticResults`,
//! and an action can opt into one via `runtimeConfiguration.staticResult.name`.
//! Two responsibilities:
//!   * `validate_runtime_static_result` — action-only sanity of the reference:
//!     shape of the `staticResult` object, valid `staticResultOptions` enum,
//!     and existence of the referenced entry.
//!   * `validate_static_results` — the declaration table itself: status enum,
//!     outputs presence, and per-type cross-checks. HTTP + Succeeded requires a
//!     stringified `statusCode`; Failed requires a non-empty `errors[].message`.

use super::materialized::arm_optional_property_absent;
use super::*;

// staticResultOptions gates whether the mock is active.
const STATIC_RESULT_OPTIONS: &[&str] = &["Disabled", "Enabled"];
// Statuses accepted for a staticResults entry (subset of run-time statuses).
const STATIC_RESULT_STATUSES: &[&str] = &["Cancelled", "Failed", "Skipped", "Succeeded"];

/// Validate an action's `runtimeConfiguration.staticResult` reference.
pub(super) fn validate_runtime_static_result(
    site: runtime::RuntimeSite<'_, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(static_result) = get(site.runtime, "staticResult") else {
        return;
    };
    if arm_optional_property_absent(site.file, static_result) {
        return;
    }
    let static_pointer = pointer_join(site.pointer, "staticResult");
    if site.label == "trigger" {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &site.file.path,
            static_pointer,
            Some(span(static_result)),
            "trigger runtimeConfiguration.staticResult is only supported on actions",
        ));
        return;
    }
    if is_opaque_arm_expression(site.file, static_result) {
        return;
    }
    if as_object(static_result).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &site.file.path,
            static_pointer,
            Some(span(static_result)),
            format!(
                "{} runtimeConfiguration.staticResult must be an object",
                site.label
            ),
        ));
        return;
    }
    require_typed_field(
        static_result,
        &static_pointer,
        "name",
        "runtimeConfiguration.staticResult.name must be a string",
        site.file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    validate_required_string_enum(
        static_result,
        &static_pointer,
        "staticResultOptions",
        &format!(
            "{} runtimeConfiguration.staticResult.staticResultOptions",
            site.label
        ),
        STATIC_RESULT_OPTIONS,
        site.file,
        diagnostics,
    );
    let Some(name_value) = get(static_result, "name") else {
        return;
    };
    if is_opaque_arm_expression(site.file, name_value) {
        return;
    }
    let Some(name) = as_string(name_value) else {
        return;
    };
    // If `definition.staticResults` is itself an opaque ARM expression we
    // cannot enumerate the declared entries, so accept the reference.
    if get(site.workflow.definition, "staticResults")
        .is_some_and(|static_results| is_opaque_arm_expression(site.file, static_results))
    {
        return;
    }
    if !static_result_entry_exists(site.file, site.workflow.definition, name) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-reference",
            &site.file.path,
            pointer_join(&static_pointer, "name"),
            Some(span(name_value)),
            format!("{} runtimeConfiguration.staticResult references missing staticResults entry '{name}'", site.label),
        ));
    }
}

/// Validate the `definition.staticResults` table.
pub(super) fn validate_static_results(
    definition: &json_spanned_value::spanned::Value,
    definition_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(static_results) = get(definition, "staticResults") else {
        return;
    };
    if arm_optional_property_absent(file, static_results) {
        return;
    }
    if is_opaque_arm_expression(file, static_results) {
        return;
    }
    let static_results_pointer = pointer_join(definition_pointer, "staticResults");
    let Some(entries) = as_object(static_results) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            static_results_pointer,
            Some(span(static_results)),
            "definition.staticResults must be an object",
        ));
        return;
    };
    for (name, entry) in entries.iter() {
        if arm_optional_property_absent(file, entry) {
            continue;
        }
        let entry_pointer = pointer_join(&static_results_pointer, name);
        if is_opaque_arm_expression(file, entry) {
            continue;
        }
        if as_object(entry).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                entry_pointer,
                Some(span(entry)),
                "staticResults entries must be objects",
            ));
            continue;
        }
        if get(entry, "status").is_none_or(|value| arm_optional_property_absent(file, value)) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-missing-field",
                &file.path,
                pointer_join(&entry_pointer, "status"),
                Some(span(entry)),
                "staticResults entry is missing required field 'status'",
            ));
        } else {
            validate_optional_string_enum(
                entry,
                &entry_pointer,
                "status",
                "staticResults status",
                STATIC_RESULT_STATUSES,
                file,
                diagnostics,
            );
        }
        let status = get(entry, "status")
            .filter(|value| !arm_optional_property_absent(file, value))
            .and_then(as_string);
        if get(entry, "outputs").is_none_or(|value| arm_optional_property_absent(file, value)) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-missing-field",
                &file.path,
                pointer_join(&entry_pointer, "outputs"),
                Some(span(entry)),
                "staticResults entry is missing required field 'outputs'",
            ));
        } else {
            validate_optional_object_field(
                entry,
                &entry_pointer,
                "outputs",
                "staticResults outputs",
                file,
                diagnostics,
            );
            // HTTP Succeeded mocks must ship a `statusCode` string so the
            // runtime has something to project into `outputs.statusCode`.
            if status.is_some_and(|status| status.eq_ignore_ascii_case("Succeeded"))
                && static_result_action_type(workflow, name)
                    .is_some_and(|action_type| action_type.eq_ignore_ascii_case("Http"))
                && let Some(outputs) = get(entry, "outputs")
                && as_object(outputs).is_some()
            {
                let status_code_pointer =
                    pointer_join(&pointer_join(&entry_pointer, "outputs"), "statusCode");
                match get(outputs, "statusCode") {
                    Some(status_code) => {
                        if as_string(status_code).is_none() {
                            diagnostics.push(Diagnostic::error(
                                "workflow-shape-invalid-type",
                                &file.path,
                                status_code_pointer,
                                Some(span(status_code)),
                                "HTTP Succeeded staticResults outputs.statusCode must be a string",
                            ));
                        }
                    }
                    None => diagnostics.push(Diagnostic::error(
                        "workflow-shape-missing-field",
                        &file.path,
                        status_code_pointer,
                        Some(span(outputs)),
                        "HTTP Succeeded staticResults outputs is missing required field 'statusCode'",
                    )),
                }
            }
            // Failed mocks must ship a non-empty `errors` array whose entries
            // each carry a message string — this is what surfaces to the run
            // failure UI.
            if status.is_some_and(|status| status.eq_ignore_ascii_case("Failed"))
                && let Some(outputs) = get(entry, "outputs")
                && as_object(outputs).is_some()
            {
                let errors_pointer =
                    pointer_join(&pointer_join(&entry_pointer, "outputs"), "errors");
                if let Some(errors) = get(outputs, "errors") {
                    if let Some(error_entries) = errors.as_span_array() {
                        if error_entries.is_empty() {
                            diagnostics.push(Diagnostic::error(
                                "workflow-shape-invalid-value",
                                &file.path,
                                &errors_pointer,
                                Some(span(errors)),
                                "failed staticResults outputs.errors must contain at least one error",
                            ));
                        }
                        for (index, error) in error_entries.iter().enumerate() {
                            let error_pointer = pointer_join(&errors_pointer, &index.to_string());
                            if as_object(error).is_none() {
                                diagnostics.push(Diagnostic::error(
                                    "workflow-shape-invalid-type",
                                    &file.path,
                                    error_pointer,
                                    Some(span(error)),
                                    "failed staticResults outputs.errors entries must be objects",
                                ));
                            } else if get(error, "message")
                                .is_none_or(|value| arm_optional_property_absent(file, value))
                            {
                                diagnostics.push(Diagnostic::error(
                                    "workflow-shape-missing-field",
                                    &file.path,
                                    pointer_join(&error_pointer, "message"),
                                    Some(span(error)),
                                    "failed staticResults outputs.errors entries must define message",
                                ));
                            } else {
                                validate_optional_string_field(
                                    error,
                                    &error_pointer,
                                    "message",
                                    "failed staticResults outputs.errors message",
                                    file,
                                    diagnostics,
                                );
                            }
                        }
                    } else {
                        diagnostics.push(Diagnostic::error(
                            "workflow-shape-invalid-type",
                            &file.path,
                            &errors_pointer,
                            Some(span(errors)),
                            "failed staticResults outputs.errors must be an array",
                        ));
                    }
                } else {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-missing-field",
                        &file.path,
                        &errors_pointer,
                        Some(span(outputs)),
                        "failed staticResults outputs must define errors",
                    ));
                }
            }
        }
        validate_optional_object_field(
            entry,
            &entry_pointer,
            "error",
            "staticResults error",
            file,
            diagnostics,
        );
    }
}

fn static_result_entry_exists(
    file: &JsonFile,
    definition: &json_spanned_value::spanned::Value,
    name: &str,
) -> bool {
    let Some(static_results) = get(definition, "staticResults") else {
        return false;
    };
    let Some(entry) = get(static_results, name) else {
        return false;
    };
    !arm_optional_property_absent(file, entry)
}

/// Look up which action binds the given `staticResult` name so we can specialize
/// the outputs check by action type. Returns the *first* binding — duplicates
/// are a separate diagnostic emitted elsewhere.
fn static_result_action_type<'a>(
    workflow: &'a Workflow<'_>,
    static_result_name: &str,
) -> Option<&'a str> {
    for action in &workflow.action_list {
        let Some(action_node) = workflow.node_at(&action.pointer) else {
            continue;
        };
        let Some(name) = get(action_node, "runtimeConfiguration")
            .and_then(|runtime| get(runtime, "staticResult"))
            .and_then(|static_result| get(static_result, "name"))
            .and_then(as_string)
        else {
            continue;
        };
        if name == static_result_name {
            return action.action_type.as_deref();
        }
    }
    None
}
