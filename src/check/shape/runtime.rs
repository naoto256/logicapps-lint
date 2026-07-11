//! `runtimeConfiguration` block validator.
//!
//! Delegates each nested sub-block to the topical module while enforcing the
//! rules that live at this level: concurrency ranges (runs 1..=100,
//! repetitions 1..=50), where `maximumWaitingRuns` may appear (nested under
//! concurrency, trigger-only, capped at 200 for Standard triggers and 100
//! elsewhere), and the `paginationPolicy.minimumItemCount` requirement.

use super::materialized::arm_optional_property_absent;
use super::*;

/// Bundle of pointers passed through the runtime validator. Grouping them
/// keeps the many downstream helpers to a single argument.
#[derive(Clone, Copy)]
struct RuntimeOperation<'a, 'w> {
    value: &'a json_spanned_value::spanned::Value,
    pointer: &'a str,
    label: &'a str,
    file: &'a JsonFile,
    workflow: &'a Workflow<'w>,
    arm_scope: crate::arm::ArmStaticScope<'a>,
}

/// View passed to the per-topic runtime validators (content_transfer,
/// secure_data, static_results, ...). `operation_type_known` distinguishes the
/// well-typed dispatch from the dynamic dispatch — some checks (Foreach-only
/// options, per-type support) only fire when the type is statically resolved.
#[derive(Clone, Copy)]
pub(super) struct RuntimeSite<'a, 'w> {
    pub(super) operation: &'a json_spanned_value::spanned::Value,
    pub(super) operation_type_known: bool,
    pub(super) runtime: &'a json_spanned_value::spanned::Value,
    pub(super) pointer: &'a str,
    pub(super) label: &'a str,
    pub(super) file: &'a JsonFile,
    pub(super) workflow: &'a Workflow<'w>,
    pub(super) arm_scope: crate::arm::ArmStaticScope<'a>,
}

/// Entry point when the operation type is statically known.
pub(super) fn validate_runtime_configuration(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    label: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_runtime_configuration_inner(
        RuntimeOperation {
            value,
            pointer,
            label,
            file,
            workflow,
            arm_scope,
        },
        true,
        diagnostics,
    );
}

/// Entry point for operations whose type is an unresolved ARM/WDL expression.
/// The type-specific context checks are suppressed to avoid false positives.
pub(super) fn validate_runtime_configuration_for_dynamic_type(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    label: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_runtime_configuration_inner(
        RuntimeOperation {
            value,
            pointer,
            label,
            file,
            workflow,
            arm_scope,
        },
        false,
        diagnostics,
    );
}

fn validate_runtime_configuration_inner(
    operation: RuntimeOperation<'_, '_>,
    operation_type_known: bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let RuntimeOperation {
        value,
        pointer,
        label,
        file,
        workflow,
        arm_scope,
    } = operation;
    let Some(runtime) = get(value, "runtimeConfiguration") else {
        return;
    };
    if arm_optional_property_absent(file, runtime) {
        return;
    }
    if is_opaque_arm_expression(file, runtime) || as_object(runtime).is_none() {
        return;
    }
    let runtime_pointer = pointer_join(pointer, "runtimeConfiguration");
    let site = RuntimeSite {
        operation: value,
        operation_type_known,
        runtime,
        pointer: &runtime_pointer,
        label,
        file,
        workflow,
        arm_scope,
    };
    if let Some(concurrency) = get(runtime, "concurrency") {
        if arm_optional_property_absent(file, concurrency) {
        } else if !is_opaque_arm_expression(file, concurrency) {
            let concurrency_pointer = pointer_join(&runtime_pointer, "concurrency");
            if as_object(concurrency).is_none() {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-type",
                    &file.path,
                    concurrency_pointer,
                    Some(span(concurrency)),
                    format!("{label} runtimeConfiguration.concurrency must be an object"),
                ));
            } else {
                // runs: trigger-only; 1..=100. Stateless workflows forbid it.
                validate_optional_integer_range(
                    concurrency,
                    &concurrency_pointer,
                    "runs",
                    &format!("{label} runtimeConfiguration.concurrency.runs"),
                    (1, 100),
                    file,
                    diagnostics,
                );
                if label != "trigger"
                    && let Some(runs) = get(concurrency, "runs")
                    && !arm_optional_property_absent(file, runs)
                {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-invalid-context",
                        &file.path,
                        pointer_join(&concurrency_pointer, "runs"),
                        Some(span(runs)),
                        format!("{label} runtimeConfiguration.concurrency.runs is only supported on triggers"),
                    ));
                }
                if label == "trigger"
                    && workflow.is_stateless()
                    && let Some(runs) = get(concurrency, "runs")
                    && !arm_optional_property_absent(file, runs)
                {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-invalid-context",
                        &file.path,
                        pointer_join(&concurrency_pointer, "runs"),
                        Some(span(runs)),
                        "trigger runtimeConfiguration.concurrency.runs is not supported in Stateless workflows",
                    ));
                }
                // repetitions: Foreach-action-only; 1..=50.
                validate_optional_integer_range(
                    concurrency,
                    &concurrency_pointer,
                    "repetitions",
                    &format!("{label} runtimeConfiguration.concurrency.repetitions"),
                    (1, 50),
                    file,
                    diagnostics,
                );
                if (label != "action"
                    || (site.operation_type_known && !common::is_foreach_action(value)))
                    && let Some(repetitions) = get(concurrency, "repetitions")
                    && !arm_optional_property_absent(file, repetitions)
                {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-invalid-context",
                        &file.path,
                        pointer_join(&concurrency_pointer, "repetitions"),
                        Some(span(repetitions)),
                        format!(
                            "{label} runtimeConfiguration.concurrency.repetitions is only supported on Foreach actions"
                        ),
                    ));
                }
                validate_concurrency_maximum_waiting_runs(
                    site,
                    concurrency,
                    &concurrency_pointer,
                    diagnostics,
                );
            }
        }
    }
    validate_top_level_maximum_waiting_runs(site, diagnostics);
    validate_runtime_pagination_policy(site, diagnostics);
    content_transfer::validate_runtime_content_transfer(site, diagnostics);
    secure_data::validate_runtime_secure_data(site, diagnostics);
    static_results::validate_runtime_static_result(site, diagnostics);
}

/// `maximumWaitingRuns` at the runtimeConfiguration root is a common mistake —
/// it belongs under `runtimeConfiguration.concurrency`. Flag it explicitly.
fn validate_top_level_maximum_waiting_runs(
    site: RuntimeSite<'_, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(maximum_waiting_runs) = get(site.runtime, "maximumWaitingRuns") else {
        return;
    };
    if arm_optional_property_absent(site.file, maximum_waiting_runs)
        || is_opaque_arm_expression(site.file, maximum_waiting_runs)
    {
        return;
    }
    diagnostics.push(Diagnostic::error(
        "workflow-shape-invalid-context",
        &site.file.path,
        pointer_join(site.pointer, "maximumWaitingRuns"),
        Some(span(maximum_waiting_runs)),
        format!(
            "{} runtimeConfiguration.maximumWaitingRuns must be under runtimeConfiguration.concurrency",
            site.label
        ),
    ));
}

fn validate_concurrency_maximum_waiting_runs(
    site: RuntimeSite<'_, '_>,
    concurrency: &json_spanned_value::spanned::Value,
    concurrency_pointer: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(maximum_waiting_runs) = get(concurrency, "maximumWaitingRuns") else {
        return;
    };
    if arm_optional_property_absent(site.file, maximum_waiting_runs)
        || is_opaque_arm_expression(site.file, maximum_waiting_runs)
    {
        return;
    }
    let pointer = pointer_join(concurrency_pointer, "maximumWaitingRuns");
    validate_maximum_waiting_runs(
        MaximumWaitingRunsCheck {
            site,
            concurrency: Some(concurrency),
            maximum_waiting_runs,
            pointer,
            field_label: "runtimeConfiguration.concurrency.maximumWaitingRuns",
        },
        diagnostics,
    );
}

struct MaximumWaitingRunsCheck<'a, 'w> {
    site: RuntimeSite<'a, 'w>,
    concurrency: Option<&'a json_spanned_value::spanned::Value>,
    maximum_waiting_runs: &'a json_spanned_value::spanned::Value,
    pointer: String,
    field_label: &'static str,
}

/// Enforce `maximumWaitingRuns` shape and range.
///
/// It applies to triggers only; the upper bound is 200 on Standard triggers and
/// 100 elsewhere; the lower bound depends on the effective concurrency (runs +
/// 10, or 11 when `SingleInstance` is the effective limiter). Stateless
/// workflows and `Recurrence` triggers do not support it at all.
fn validate_maximum_waiting_runs(
    check: MaximumWaitingRunsCheck<'_, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if check.site.label != "trigger" {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &check.site.file.path,
            check.pointer.clone(),
            Some(span(check.maximum_waiting_runs)),
            format!(
                "{} {} is only supported on triggers",
                check.site.label, check.field_label
            ),
        ));
    }
    let Some(waiting_runs) = integer_value(check.maximum_waiting_runs) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &check.site.file.path,
            check.pointer.clone(),
            Some(span(check.maximum_waiting_runs)),
            format!(
                "{} {} must be an integer",
                check.site.label, check.field_label
            ),
        ));
        return;
    };
    // Standard triggers double the cap; Consumption stays at 100.
    let max_waiting_runs = if check.site.label == "trigger" && check.site.workflow.is_standard() {
        200
    } else {
        100
    };
    let runs = check
        .concurrency
        .and_then(|concurrency| get(concurrency, "runs"))
        .filter(|runs| !arm_optional_property_absent(check.site.file, runs));
    let runs_value = runs
        .filter(|runs| !is_opaque_arm_expression(check.site.file, runs))
        .and_then(integer_value);
    let operation_options_value = get(check.site.operation, "operationOptions");
    let operation_options = operation_options_value.and_then(as_string);
    let single_instance_enabled = operation_options.is_some_and(|options| {
        operation_options::operation_option_enabled(options, "SingleInstance")
    });
    let operation_options_opaque = operation_options_value
        .is_some_and(|value| is_opaque_arm_expression(check.site.file, value));
    // If operationOptions is dynamic (WDL expression or opaque ARM), assume the
    // SingleInstance token *could* be produced at runtime and skip the "requires
    // runs or SingleInstance" diagnostic.
    let single_instance_dynamic =
        operation_options.is_some_and(wdl_string_has_dynamic_value) || operation_options_opaque;
    if check.site.label == "trigger"
        && runs.is_none()
        && !single_instance_enabled
        && !single_instance_dynamic
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &check.site.file.path,
            check.pointer.clone(),
            Some(span(check.maximum_waiting_runs)),
            format!(
                "{} {} requires runtimeConfiguration.concurrency.runs or operationOptions SingleInstance",
                check.site.label, check.field_label
            ),
        ));
    }
    let min_waiting_runs = runs_value
        .or_else(|| single_instance_enabled.then_some(1))
        .map(|runs| runs + 10)
        .unwrap_or(1);
    if waiting_runs < min_waiting_runs || waiting_runs > max_waiting_runs {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &check.site.file.path,
            check.pointer.clone(),
            Some(span(check.maximum_waiting_runs)),
            format!(
                "{} {} value {waiting_runs} is out of range",
                check.site.label, check.field_label
            ),
        ));
    }
    if check.site.label == "trigger" && check.site.workflow.is_stateless() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &check.site.file.path,
            check.pointer.clone(),
            Some(span(check.maximum_waiting_runs)),
            format!(
                "trigger {} is not supported in Stateless workflows",
                check.field_label
            ),
        ));
    }
    if check.site.label == "trigger"
        && check.site.operation_type_known
        && common::node_type_is_one_of(check.site.operation, &["Recurrence"])
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &check.site.file.path,
            check.pointer,
            Some(span(check.maximum_waiting_runs)),
            format!("Recurrence trigger {} is not supported", check.field_label),
        ));
    }
}

/// paginationPolicy is action-only, must be an object, and requires
/// `minimumItemCount` (a positive integer).
fn validate_runtime_pagination_policy(
    site: RuntimeSite<'_, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(policy) = get(site.runtime, "paginationPolicy") else {
        return;
    };
    if arm_optional_property_absent(site.file, policy)
        || is_opaque_arm_expression(site.file, policy)
    {
        return;
    }
    let policy_pointer = pointer_join(site.pointer, "paginationPolicy");
    if site.label != "action" {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &site.file.path,
            policy_pointer.clone(),
            Some(span(policy)),
            format!(
                "{} runtimeConfiguration.paginationPolicy is only supported on actions",
                site.label
            ),
        ));
    }
    if as_object(policy).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &site.file.path,
            policy_pointer,
            Some(span(policy)),
            format!(
                "{} runtimeConfiguration.paginationPolicy must be an object",
                site.label
            ),
        ));
        return;
    }
    if get(policy, "minimumItemCount")
        .is_none_or(|value| arm_optional_property_absent(site.file, value))
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &site.file.path,
            pointer_join(&policy_pointer, "minimumItemCount"),
            Some(span(policy)),
            format!(
                "{} runtimeConfiguration.paginationPolicy is missing required field 'minimumItemCount'",
                site.label
            ),
        ));
    }
    validate_optional_positive_integer(
        policy,
        &policy_pointer,
        "minimumItemCount",
        &format!(
            "{} runtimeConfiguration.paginationPolicy.minimumItemCount",
            site.label
        ),
        site.file,
        diagnostics,
    );
}
