//! Shape validators for the control-flow action family: `Foreach`, `Until`,
//! `If`, `Scope`, `Switch`, `Response`, `Terminate`, and `Wait`. In addition
//! to per-field shape checks, several of these enforce structural rules on
//! how the action may be placed in the workflow graph (e.g. `Response` needs
//! a Request trigger and cannot sit in an unjoined parallel branch).

use super::super::materialized::{arm_optional_property_absent, static_json_value_from_spanned};
use super::*;
use crate::json::to_json_value;

const TERMINATE_RUN_STATUSES: &[&str] = &["Cancelled", "Failed", "Succeeded"];

/// Validate a `Foreach` action: the loop needs an iterable (`foreach` — a WDL
/// string expression or literal array) and a child `actions` container.
pub(in crate::check::shape) fn validate_foreach_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    require_field(action, action_pointer, "foreach", file, diagnostics);
    validate_foreach_expression(action, action_pointer, file, diagnostics);
    require_object_field(action, action_pointer, "actions", file, diagnostics);
}

pub(in crate::check::shape) fn validate_foreach_expression(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(action, "foreach") else {
        return;
    };
    if as_string(value).is_none() && value.as_array().is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(action_pointer, "foreach"),
            Some(span(value)),
            "Foreach.foreach must be a string or array",
        ));
    }
}

/// Validate an `Until` action. The runtime treats stateless and stateful
/// hosts as having different max-iteration / max-timeout envelopes; we defer
/// the split to [`validate_until_limit`] via `is_stateless`.
pub(in crate::check::shape) fn validate_until_action_with_workflow(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_until_action_with_limit(
        action,
        action_pointer,
        file,
        workflow.is_stateless(),
        diagnostics,
    );
}

fn validate_until_action_with_limit(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    stateless: bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    require_field(action, action_pointer, "expression", file, diagnostics);
    validate_until_expression(action, action_pointer, file, diagnostics);
    require_object_field(action, action_pointer, "actions", file, diagnostics);
    require_until_limit_field(action, action_pointer, file, diagnostics);
    validate_until_limit(action, action_pointer, file, stateless, diagnostics);
}

fn require_until_limit_field(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if get(action, "limit").is_none_or(|limit| arm_optional_property_absent(file, limit)) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(action_pointer, "limit"),
            Some(span(action)),
            "action is missing required field 'limit'",
        ));
    }
}

pub(in crate::check::shape) fn validate_until_expression(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(action, "expression") else {
        return;
    };
    if as_string(value).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(action_pointer, "expression"),
            Some(span(value)),
            "Until expression must be a string",
        ));
    }
}

/// Validate an `If` action: boolean `expression` (string or condition object)
/// plus `actions`. The optional `else` branch, when present, must itself have
/// an `actions` container so both branches are executable.
pub(in crate::check::shape) fn validate_if_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    require_field(action, action_pointer, "expression", file, diagnostics);
    validate_if_expression(action, action_pointer, file, diagnostics);
    require_object_field(action, action_pointer, "actions", file, diagnostics);
    if let Some(else_branch) = get(action, "else") {
        require_object_field(
            else_branch,
            &pointer_join(action_pointer, "else"),
            "actions",
            file,
            diagnostics,
        );
    }
}

pub(in crate::check::shape) fn validate_if_expression(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(action, "expression") else {
        return;
    };
    if as_string(value).is_none() && as_object(value).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(action_pointer, "expression"),
            Some(span(value)),
            "If expression must be a string or object",
        ));
    }
}

/// Validate a `Scope` action: a container that only requires `actions`.
pub(in crate::check::shape) fn validate_scope_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    require_object_field(action, action_pointer, "actions", file, diagnostics);
}

/// Validate a `Switch` action: `expression` selects the branch, `cases` maps
/// case names to `{ case, actions }` objects, and `default.actions` is the
/// optional fallthrough. Duplicate case values across branches are rejected.
pub(in crate::check::shape) fn validate_switch_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    require_field(action, action_pointer, "expression", file, diagnostics);
    require_object_field(action, action_pointer, "cases", file, diagnostics);
    validate_switch_expression(action, action_pointer, file, diagnostics);
    validate_switch_cases(action, action_pointer, file, diagnostics);
    if let Some(default_branch) = get(action, "default") {
        validate_optional_object_field(
            action,
            action_pointer,
            "default",
            "Switch default",
            file,
            diagnostics,
        );
        validate_optional_object_field(
            default_branch,
            &pointer_join(action_pointer, "default"),
            "actions",
            "Switch default actions",
            file,
            diagnostics,
        );
    }
}

pub(in crate::check::shape) fn validate_switch_expression(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(expression) = get(action, "expression") else {
        return;
    };
    if as_string(expression).is_none() && expression.as_number().is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(action_pointer, "expression"),
            Some(span(expression)),
            "Switch expression must be a string or number",
        ));
    }
}

/// Validate a `Response` action. Contextual rules beyond input shape:
/// (1) requires a `Request` trigger to reply to; (2) cannot sit inside a
/// `Foreach`/`Until` (many synthetic responses per run make no sense);
/// (3) cannot be one branch of an unjoined parallel fan-out; (4) in a
/// Stateless workflow must be the terminal action before any successor.
pub(in crate::check::shape) fn validate_response_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !workflow_has_request_trigger(workflow) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            action_pointer.to_owned(),
            Some(span(action)),
            "Response actions require a Request trigger",
        ));
    }
    if action_is_nested_under_kind(
        workflow,
        action_pointer,
        &[ActionKind::Foreach, ActionKind::Until],
    ) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            action_pointer.to_owned(),
            Some(span(action)),
            "Response actions cannot be nested inside Foreach or Until actions",
        ));
    }
    if let Some(dependency) = response_parallel_dependency(action, action_pointer, workflow) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(action_pointer, "runAfter"),
            get(action, "runAfter").map(span),
            format!("Response action cannot be placed in a parallel branch after '{dependency}'"),
        ));
    }
    if workflow.is_stateless()
        && let Some(successor) = stateless_response_successor(action_pointer, workflow)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            action_pointer.to_owned(),
            Some(span(action)),
            format!("Response action must be the last action in a Stateless workflow before '{successor}'"),
        ));
    }
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    let inputs_pointer = pointer_join(action_pointer, "inputs");
    require_typed_field(
        inputs,
        &inputs_pointer,
        "statusCode",
        "Response inputs.statusCode must be an integer or string",
        file,
        diagnostics,
        |value| as_string(value).is_some() || is_integer_value(value),
    );
    if let Some(status_code) = get(inputs, "statusCode")
        && !is_opaque_arm_expression(file, status_code)
        && let Some(status_code_text) = as_string(status_code)
        && !is_wdl_expression_string(status_code_text)
        && status_code_text.parse::<i64>().is_err()
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(&inputs_pointer, "statusCode"),
            Some(span(status_code)),
            "Response inputs.statusCode must be an HTTP status code or expression string",
        ));
    }
    if let Some(status_code) = get(inputs, "statusCode")
        && !is_opaque_arm_expression(file, status_code)
        && let Some(code) = integer_or_integer_string_value(status_code)
        // Response can only surface 2xx (success) or 4xx/5xx (error);
        // 1xx/3xx are meaningless for a fire-and-forget HTTP response.
        && !(200..=299).contains(&code)
        && !(400..=599).contains(&code)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(&inputs_pointer, "statusCode"),
            Some(span(status_code)),
            format!("Response inputs.statusCode value {code} is not supported"),
        ));
    }
    validate_optional_object_or_string_field(
        inputs,
        &inputs_pointer,
        "headers",
        "Response inputs.headers",
        file,
        diagnostics,
    );
}

fn is_wdl_expression_string(value: &str) -> bool {
    value.starts_with('@') && !value.starts_with("@@")
}

/// Validate a `Terminate` action: `runStatus` is one of a fixed set, and
/// `runError` is meaningful only when `runStatus` is `Failed`. Also cannot
/// live inside `Foreach`/`Until` — terminating the run from inside a loop
/// iteration is ambiguous per the runtime.
pub(in crate::check::shape) fn validate_terminate_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if action_is_nested_under_kind(
        workflow,
        action_pointer,
        &[ActionKind::Foreach, ActionKind::Until],
    ) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            action_pointer.to_owned(),
            Some(span(action)),
            "Terminate actions cannot be nested inside Foreach or Until actions",
        ));
    }
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    require_typed_field(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "runStatus",
        "Terminate inputs.runStatus must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    validate_optional_string_enum(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "runStatus",
        "Terminate inputs.runStatus",
        TERMINATE_RUN_STATUSES,
        file,
        diagnostics,
    );
    validate_terminate_run_error(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        file,
        diagnostics,
    );
}

pub(in crate::check::shape) fn validate_terminate_run_error(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(run_error) = get(inputs, "runError") else {
        return;
    };
    if get(inputs, "runStatus")
        .and_then(as_string)
        .is_some_and(|status| status != "Failed")
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(inputs_pointer, "runError"),
            Some(span(run_error)),
            "Terminate inputs.runError can only be used when runStatus is Failed",
        ));
    }
    if is_opaque_arm_expression(file, run_error) {
        return;
    }
    let run_error_pointer = pointer_join(inputs_pointer, "runError");
    if as_object(run_error).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            run_error_pointer,
            Some(span(run_error)),
            "Terminate inputs.runError must be an object",
        ));
        return;
    }
    require_typed_field(
        run_error,
        &run_error_pointer,
        "code",
        "Terminate inputs.runError.code must be a number or string",
        file,
        diagnostics,
        |value| as_string(value).is_some() || value.as_number().is_some(),
    );
    require_typed_field(
        run_error,
        &run_error_pointer,
        "message",
        "Terminate inputs.runError.message must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
}

/// Validate a `Wait` action: exactly one of `interval` (relative) or `until`
/// (absolute timestamp). Extra static keys are treated as author mistakes.
pub(in crate::check::shape) fn validate_wait_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    let inputs_pointer = pointer_join(action_pointer, "inputs");
    let has_interval = get(inputs, "interval").is_some();
    let has_until = get(inputs, "until").is_some();
    if let Some(inputs_object) = as_object(inputs) {
        // Wait is one of the few actions where extra static keys are likely
        // authoring mistakes: it is either a duration or an absolute timestamp.
        let property_count = inputs_object.len();
        if property_count > 1 && !(property_count == 2 && has_interval && has_until) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-shape",
                &file.path,
                inputs_pointer.clone(),
                Some(span(inputs)),
                "Wait inputs must contain only one property",
            ));
        }
    }
    if has_interval && has_until {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-shape",
            &file.path,
            inputs_pointer.clone(),
            Some(span(inputs)),
            "Wait inputs must define only one of 'interval' or 'until'",
        ));
    } else if !has_interval && !has_until {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            inputs_pointer.clone(),
            Some(span(inputs)),
            "Wait inputs must define 'interval' or 'until'",
        ));
    }
    if let Some(interval) = get(inputs, "interval") {
        if is_opaque_arm_expression(file, interval) {
            return;
        } else if as_object(interval).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                pointer_join(&inputs_pointer, "interval"),
                Some(span(interval)),
                "Wait inputs.interval must be an object",
            ));
        } else {
            validate_optional_string_enum(
                interval,
                &pointer_join(&inputs_pointer, "interval"),
                "unit",
                "Wait inputs.interval.unit",
                TIME_UNITS,
                file,
                diagnostics,
            );
            require_typed_field(
                interval,
                &pointer_join(&inputs_pointer, "interval"),
                "unit",
                "Wait inputs.interval.unit must be a string",
                file,
                diagnostics,
                |value| as_string(value).is_some(),
            );
            require_typed_field(
                interval,
                &pointer_join(&inputs_pointer, "interval"),
                "count",
                "Wait inputs.interval.count must be an integer",
                file,
                diagnostics,
                // The runtime evaluates `count` when it fires the Wait, so a
                // parameterized value like `@parameters('delayInMinutes')` is
                // legal. Only structural non-integers (booleans, objects,
                // arrays, arbitrary strings) are flagged.
                is_integer_or_wdl_expression,
            );
        }
    }
    if let Some(until) = get(inputs, "until") {
        if is_opaque_arm_expression(file, until) {
            // ARM template evaluation can provide the statically required object.
        } else if as_object(until).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                pointer_join(&inputs_pointer, "until"),
                Some(span(until)),
                "Wait inputs.until must be an object",
            ));
        } else {
            require_typed_field(
                until,
                &pointer_join(&inputs_pointer, "until"),
                "timestamp",
                "Wait inputs.until.timestamp must be a string",
                file,
                diagnostics,
                |value| as_string(value).is_some(),
            );
        }
    }
}

/// Validate an `Until.limit`. At least one of `count` or `timeout` is
/// required; `count` is bounded (1..=100 stateless, 1..=5000 stateful) and
/// `timeout` must be an ISO 8601 duration.
pub(in crate::check::shape) fn validate_until_limit(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    stateless: bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(limit) = get(action, "limit") else {
        return;
    };
    if arm_optional_property_absent(file, limit) {
        return;
    }
    if is_opaque_arm_expression(file, limit) {
        // ARM can supply the optional limit object at deployment time.
        return;
    }
    let Some(limit_object) = as_object(limit) else {
        return;
    };
    let limit_pointer = pointer_join(action_pointer, "limit");
    if !limit_object.contains_key("count") && !limit_object.contains_key("timeout") {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            limit_pointer.clone(),
            Some(span(limit)),
            "Until limit must define 'count' or 'timeout'",
        ));
    }
    if let Some(count) = get(limit, "count")
        && !arm_optional_property_absent(file, count)
        && !is_opaque_arm_expression(file, count)
        && !as_string(count).is_some_and(wdl_string_may_be_positive_integer)
        && !is_integer_value(count)
        && integer_or_integer_string_value(count).is_none()
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(&limit_pointer, "count"),
            Some(span(count)),
            "Until limit.count must be an integer",
        ));
    }
    if let Some(count) = get(limit, "count")
        && !arm_optional_property_absent(file, count)
        && !is_opaque_arm_expression(file, count)
        && let Some(value) = integer_or_integer_string_value(count)
        && (value < 1 || value > if stateless { 100 } else { 5000 })
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(&limit_pointer, "count"),
            Some(span(count)),
            format!("Until limit.count value {value} is out of range"),
        ));
    }
    if let Some(timeout) = get(limit, "timeout")
        && !arm_optional_property_absent(file, timeout)
        && !is_opaque_arm_expression(file, timeout)
    {
        match as_string(timeout) {
            Some(text) if wdl_string_may_be_iso8601_duration(text) => {}
            Some(_) => diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                pointer_join(&limit_pointer, "timeout"),
                Some(span(timeout)),
                "Until limit.timeout must be an ISO 8601 duration",
            )),
            None => diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                pointer_join(&limit_pointer, "timeout"),
                Some(span(timeout)),
                "Until limit.timeout must be a string",
            )),
        }
    }
}

/// Validate `Switch.cases`. The runtime caps at 25 branches. Each case value
/// must be static (no WDL expression could yield a compile-time discriminator)
/// and unique across the switch — later duplicates are reported once each.
pub(in crate::check::shape) fn validate_switch_cases(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(cases_value) = get(action, "cases") else {
        return;
    };
    let cases_pointer = pointer_join(action_pointer, "cases");
    limits::validate_root_object_count(
        cases_value,
        &cases_pointer,
        "Switch cases",
        25,
        file,
        diagnostics,
    );
    let Some(cases) = as_object(cases_value) else {
        return;
    };
    let mut seen_case_values = Vec::new();
    for (case_name, case_value) in cases.iter() {
        let case_pointer = pointer_join(&cases_pointer, case_name);
        if as_object(case_value).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                case_pointer,
                Some(span(case_value)),
                "Switch case entries must be objects",
            ));
            continue;
        }
        require_field(case_value, &case_pointer, "case", file, diagnostics);
        let Some(case) = get(case_value, "case") else {
            continue;
        };
        let case_value_pointer = pointer_join(&case_pointer, "case");
        if switch_case_value_is_dynamic(case, file) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                case_value_pointer,
                Some(span(case)),
                "Switch case values must be static",
            ));
            continue;
        }
        let Some(comparison_value) = switch_case_comparison_value(case, file) else {
            continue;
        };
        if let Some((_, previous_case)) = seen_case_values
            .iter()
            .find(|(value, _)| value == &comparison_value)
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                case_value_pointer,
                Some(span(case)),
                format!("Switch case value duplicates case '{previous_case}'"),
            ));
            continue;
        }
        seen_case_values.push((comparison_value, case_name));
    }
}

fn switch_case_value_is_dynamic(
    value: &json_spanned_value::spanned::Value,
    file: &JsonFile,
) -> bool {
    if let Some((materialized, _)) = static_json_value_from_spanned(file, value) {
        return materialized
            .as_str()
            .is_some_and(wdl_string_has_dynamic_value);
    }
    is_opaque_arm_expression(file, value)
        || as_string(value).is_some_and(wdl_string_has_dynamic_value)
}

fn switch_case_comparison_value(
    value: &json_spanned_value::spanned::Value,
    file: &JsonFile,
) -> Option<serde_json::Value> {
    let mut value = static_json_value_from_spanned(file, value)
        .map(|(value, _)| value)
        .or_else(|| to_json_value(value))?;
    // `@@` is the WDL literal escape for a `@`-prefixed string; unescape so
    // duplicate detection compares the value the runtime will actually see.
    if let serde_json::Value::String(text) = &mut value
        && text.starts_with("@@")
    {
        text.remove(0);
    }
    Some(value)
}

/// True if the workflow has any `Request` trigger. Checks both the cached
/// `trigger_types` map and (as fallback) the trigger nodes themselves — some
/// triggers can be materialized only via ARM evaluation.
pub(in crate::check::shape) fn workflow_has_request_trigger(workflow: &Workflow<'_>) -> bool {
    workflow
        .trigger_types
        .values()
        .any(|trigger_type| trigger_type.eq_ignore_ascii_case("Request"))
        || workflow.triggers.iter().any(|trigger_name| {
            let trigger_pointer = pointer_join(
                &pointer_join(&workflow.definition_pointer, "triggers"),
                trigger_name,
            );
            workflow
                .node_at(&trigger_pointer)
                .and_then(|trigger| get(trigger, "type"))
                .and_then(as_string)
                .is_some_and(|trigger_type| trigger_type.eq_ignore_ascii_case("Request"))
        })
}

fn stateless_response_successor(action_pointer: &str, workflow: &Workflow<'_>) -> Option<String> {
    let response = workflow
        .action_list
        .iter()
        .find(|action| action.pointer == action_pointer)?;
    workflow
        .action_list
        .iter()
        .filter(|action| {
            action.container_pointer == response.container_pointer && action.name != response.name
        })
        .find(|action| {
            action_depends_on(
                &action.name,
                &response.name,
                &response.container_pointer,
                workflow,
                &mut std::collections::BTreeSet::new(),
            )
        })
        .map(|action| action.name.clone())
}

/// If the `Response` action lives inside an unjoined parallel branch,
/// return the sibling branch that would race it — the runtime cannot
/// guarantee which branch fires the HTTP reply.
pub(in crate::check::shape) fn response_parallel_dependency(
    _action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    workflow: &Workflow<'_>,
) -> Option<String> {
    let action_info = workflow
        .action_list
        .iter()
        .find(|candidate| candidate.pointer == action_pointer)?;
    let join_dependencies = action_info
        .run_after
        .iter()
        .map(|dependency| dependency.dependency.clone())
        .collect::<std::collections::BTreeSet<_>>();
    response_parallel_dependency_from_action(
        action_info,
        workflow,
        &mut std::collections::BTreeSet::new(),
        &join_dependencies,
    )
}

fn response_parallel_dependency_from_action(
    action: &crate::workflow::ActionInfo,
    workflow: &Workflow<'_>,
    visited: &mut std::collections::BTreeSet<String>,
    join_dependencies: &std::collections::BTreeSet<String>,
) -> Option<String> {
    if !visited.insert(action.pointer.clone()) {
        return None;
    }
    if let Some(dependency) = parallel_sibling_dependency(action, workflow)
        && !parallel_group_is_joined(action, workflow, join_dependencies)
    {
        return Some(dependency);
    }
    for dependency in &action.run_after {
        let Some(upstream) = workflow.action_list.iter().find(|candidate| {
            candidate.container_pointer == action.container_pointer
                && candidate.name == dependency.dependency
        }) else {
            continue;
        };
        if let Some(dependency) =
            response_parallel_dependency_from_action(upstream, workflow, visited, join_dependencies)
        {
            return Some(dependency);
        }
    }
    None
}

fn parallel_group_is_joined(
    action: &crate::workflow::ActionInfo,
    workflow: &Workflow<'_>,
    join_dependencies: &std::collections::BTreeSet<String>,
) -> bool {
    let branches = parallel_branch_actions(action, workflow);
    branches.len() > 1
        && branches
            .iter()
            .all(|branch| branch_is_covered_by_join(branch, workflow, join_dependencies))
}

fn parallel_branch_actions<'a>(
    action: &'a crate::workflow::ActionInfo,
    workflow: &'a Workflow<'_>,
) -> Vec<&'a crate::workflow::ActionInfo> {
    let siblings = workflow
        .action_list
        .iter()
        .filter(|candidate| candidate.container_pointer == action.container_pointer);
    if action.run_after.is_empty() {
        return siblings
            .filter(|candidate| candidate.run_after.is_empty())
            .collect();
    }
    siblings
        .filter(|candidate| {
            candidate.pointer == action.pointer
                || run_after_dependencies_overlap(&action.run_after, &candidate.run_after).is_some()
        })
        .collect()
}

fn branch_is_covered_by_join(
    branch: &crate::workflow::ActionInfo,
    workflow: &Workflow<'_>,
    join_dependencies: &std::collections::BTreeSet<String>,
) -> bool {
    join_dependencies.iter().any(|dependency| {
        dependency == &branch.name
            || action_depends_on(
                dependency,
                &branch.name,
                &branch.container_pointer,
                workflow,
                &mut std::collections::BTreeSet::new(),
            )
    })
}

fn action_depends_on(
    action_name: &str,
    dependency_name: &str,
    container_pointer: &str,
    workflow: &Workflow<'_>,
    visited: &mut std::collections::BTreeSet<String>,
) -> bool {
    if !visited.insert(action_name.to_owned()) {
        return false;
    }
    let Some(action) = workflow.action_list.iter().find(|candidate| {
        candidate.container_pointer == container_pointer && candidate.name == action_name
    }) else {
        return false;
    };
    action.run_after.iter().any(|dependency| {
        dependency.dependency == dependency_name
            || action_depends_on(
                &dependency.dependency,
                dependency_name,
                container_pointer,
                workflow,
                visited,
            )
    })
}

fn parallel_sibling_dependency(
    action: &crate::workflow::ActionInfo,
    workflow: &Workflow<'_>,
) -> Option<String> {
    if action.run_after.is_empty() {
        for sibling in workflow.action_list.iter().filter(|candidate| {
            candidate.pointer != action.pointer
                && candidate.container_pointer == action.container_pointer
        }) {
            if sibling.run_after.is_empty() {
                return Some(sibling.name.clone());
            }
        }
    }
    for sibling in workflow.action_list.iter().filter(|candidate| {
        candidate.pointer != action.pointer
            && candidate.container_pointer == action.container_pointer
    }) {
        if let Some(dependency) =
            run_after_dependencies_overlap(&action.run_after, &sibling.run_after)
        {
            return Some(dependency);
        }
    }
    None
}

fn run_after_dependencies_overlap(
    left: &[crate::workflow::RunAfterDependency],
    right: &[crate::workflow::RunAfterDependency],
) -> Option<String> {
    for left_dependency in left {
        for right_dependency in right {
            if left_dependency.dependency == right_dependency.dependency
                && run_after_dependency_statuses_overlap(left_dependency, right_dependency)
            {
                return Some(left_dependency.dependency.clone());
            }
        }
    }
    None
}

fn run_after_dependency_statuses_overlap(
    left: &crate::workflow::RunAfterDependency,
    right: &crate::workflow::RunAfterDependency,
) -> bool {
    if left.statuses.is_empty() || right.statuses.is_empty() {
        return true;
    }
    left.statuses.iter().any(|left_status| {
        right
            .statuses
            .iter()
            .any(|right_status| left_status.eq_ignore_ascii_case(right_status))
    })
}

/// True if `action_pointer` is a descendant of any action whose kind is in
/// `action_kinds`. Uses pointer prefix comparison — cheap because every
/// nesting appends a `/` segment.
pub(in crate::check::shape) fn action_is_nested_under_kind(
    workflow: &Workflow<'_>,
    action_pointer: &str,
    action_kinds: &[ActionKind],
) -> bool {
    workflow.action_list.iter().any(|candidate| {
        action_pointer != candidate.pointer
            && action_pointer.starts_with(&format!("{}/", candidate.pointer))
            && action_kinds.contains(&candidate.kind)
    })
}
