//! `operationOptions` string shape and cross-field context checks.
//!
//! `operationOptions` is a comma/whitespace-separated list embedded in a single
//! string. Each token names a runtime behavior; each behavior only makes sense
//! on a specific set of action or trigger types, and some conflict with fields
//! under `runtimeConfiguration.concurrency`. Duplicate tokens are preserved on
//! purpose so this module's diagnostics line up 1:1 with the runtime's own
//! duplicate-tolerant parse.

use super::materialized::arm_optional_property_absent;
use super::*;

pub(super) const DISABLE_ASYNC_PATTERN_ACTION_TYPES: &[&str] =
    &["ApiConnection", "Http", "Response"];
pub(super) const SUPPRESS_WORKFLOW_HEADERS_ACTION_TYPES: &[&str] =
    &["ApiManagement", "Function", "Http"];
pub(super) const AUTHORIZATION_HEADERS_TRIGGER_TYPES: &[&str] = &["Request", "HttpWebhook"];
const ACTION_OPERATION_OPTIONS: &[&str] = &[
    "DisableAsyncPattern",
    "FailWhenLimitsReached",
    "Sequential",
    "SuppressWorkflowHeaders",
];
const TRIGGER_OPERATION_OPTIONS: &[&str] = &[
    "IncludeAuthorizationHeadersInOutputs",
    "SingleInstance",
    "SuppressWorkflowHeadersOnResponse",
];

/// Detect operationOptions that conflict with concurrency settings:
/// `SingleInstance` collides with `concurrency.runs`, and `Sequential` collides
/// with `concurrency.repetitions`.
pub(super) fn validate_operation_options_conflicts(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(operation_options) = get(value, "operationOptions").and_then(as_string) else {
        return;
    };
    let Some(runtime) = get(value, "runtimeConfiguration") else {
        return;
    };
    if arm_optional_property_absent(file, runtime) {
        return;
    }
    let Some(concurrency) = get(runtime, "concurrency") else {
        return;
    };
    if arm_optional_property_absent(file, concurrency) {
        return;
    }
    let runs_present =
        get(concurrency, "runs").is_some_and(|runs| !arm_optional_property_absent(file, runs));
    if operation_option_enabled(operation_options, "SingleInstance") && runs_present {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(pointer, "operationOptions"),
            get(value, "operationOptions").map(span),
            format!("{label} operationOptions SingleInstance conflicts with runtimeConfiguration.concurrency.runs"),
        ));
    }
    let repetitions_present = get(concurrency, "repetitions")
        .is_some_and(|repetitions| !arm_optional_property_absent(file, repetitions));
    if operation_option_enabled(operation_options, "Sequential") && repetitions_present {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(pointer, "operationOptions"),
            get(value, "operationOptions").map(span),
            format!("{label} operationOptions Sequential conflicts with runtimeConfiguration.concurrency.repetitions"),
        ));
    }
}

/// Validate every token in operationOptions against the allowlist for the
/// caller's role (action vs trigger), and enforce the type-specific rules
/// (`Sequential` only on Foreach, `DisableAsyncPattern` only on the async-shaped
/// action types, etc.). Called on the well-typed path where the operation type
/// is known.
pub(super) fn validate_operation_options_values(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    label: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some((operation_options_value, operation_options)) =
        operation_options_value_and_text(value, file)
    else {
        return;
    };
    for option in operation_option_tokens(operation_options) {
        let allowed = if label == "trigger" {
            TRIGGER_OPERATION_OPTIONS
        } else {
            ACTION_OPERATION_OPTIONS
        };
        let analyzed = crate::wdl::WdlStringValue::classify(option);
        if !analyzed.may_match_exact(allowed) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                pointer_join(pointer, "operationOptions"),
                Some(span(operation_options_value)),
                format!("{label} operationOptions '{option}' is not supported"),
            ));
            continue;
        }
        let Some(option) = analyzed.literal() else {
            continue;
        };
        if label == "action" && option == "Sequential" && !common::is_foreach_action(value) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &file.path,
                pointer_join(pointer, "operationOptions"),
                Some(span(operation_options_value)),
                "action operationOptions Sequential is only supported on Foreach actions",
            ));
        } else if label == "action"
            && option == "DisableAsyncPattern"
            && !common::node_type_is_one_of(value, DISABLE_ASYNC_PATTERN_ACTION_TYPES)
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &file.path,
                pointer_join(pointer, "operationOptions"),
                Some(span(operation_options_value)),
                "action operationOptions DisableAsyncPattern is only supported on ApiConnection, Http, and Response actions",
            ));
        } else if label == "action"
            && option == "SuppressWorkflowHeaders"
            && !common::node_type_is_one_of(value, SUPPRESS_WORKFLOW_HEADERS_ACTION_TYPES)
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &file.path,
                pointer_join(pointer, "operationOptions"),
                Some(span(operation_options_value)),
                "action operationOptions SuppressWorkflowHeaders is only supported on ApiManagement, Function, and Http actions",
            ));
        } else if label == "action"
            && option == "FailWhenLimitsReached"
            && !common::node_type_is_one_of(value, &["Until"])
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &file.path,
                pointer_join(pointer, "operationOptions"),
                Some(span(operation_options_value)),
                "action operationOptions FailWhenLimitsReached is only supported on Until actions",
            ));
        } else if label == "trigger" && option == "SingleInstance" && workflow.is_stateless() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &file.path,
                pointer_join(pointer, "operationOptions"),
                Some(span(operation_options_value)),
                "trigger operationOptions SingleInstance is not supported in Stateless workflows",
            ));
        } else if label == "trigger"
            && option == "SuppressWorkflowHeadersOnResponse"
            && !common::node_type_is_one_of(value, AUTHORIZATION_HEADERS_TRIGGER_TYPES)
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &file.path,
                pointer_join(pointer, "operationOptions"),
                Some(span(operation_options_value)),
                "trigger operationOptions SuppressWorkflowHeadersOnResponse is only supported on Request and HttpWebhook triggers",
            ));
        } else if label == "trigger"
            && option == "IncludeAuthorizationHeadersInOutputs"
            && !common::node_type_is_one_of(value, AUTHORIZATION_HEADERS_TRIGGER_TYPES)
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &file.path,
                pointer_join(pointer, "operationOptions"),
                Some(span(operation_options_value)),
                "trigger operationOptions IncludeAuthorizationHeadersInOutputs is only supported on Request and HttpWebhook triggers",
            ));
        }
    }
}

/// Literal-only counterpart: when the operation type is unknown or dynamic, we
/// still flag tokens that could not possibly appear in the allowlist. The
/// per-type context checks are skipped because we cannot decide them.
pub(in crate::check::shape) fn validate_operation_options_literal_values(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some((operation_options_value, operation_options)) =
        operation_options_value_and_text(value, file)
    else {
        return;
    };
    for option in operation_option_tokens(operation_options) {
        let allowed = if label == "trigger" {
            TRIGGER_OPERATION_OPTIONS
        } else {
            ACTION_OPERATION_OPTIONS
        };
        if !crate::wdl::WdlStringValue::classify(option).may_match_exact(allowed) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                pointer_join(pointer, "operationOptions"),
                Some(span(operation_options_value)),
                format!("{label} operationOptions '{option}' is not supported"),
            ));
        }
    }
}

fn operation_options_value_and_text<'a>(
    value: &'a json_spanned_value::spanned::Value,
    file: &JsonFile,
) -> Option<(&'a json_spanned_value::spanned::Value, &'a str)> {
    let operation_options_value = get(value, "operationOptions")?;
    if is_opaque_arm_expression(file, operation_options_value) {
        return None;
    }
    let operation_options = as_string(operation_options_value)?;
    if crate::wdl::WdlStringValue::classify(operation_options).is_full_expression() {
        return None;
    }
    Some((operation_options_value, operation_options))
}

/// Split operationOptions into tokens on commas / whitespace, but treat any
/// `@{ ... }` WDL interpolation as a single atomic token so a value like
/// `"@{parameters('x')}, Sequential"` still parses as two options. Duplicates
/// are kept — the runtime accepts them and this parser preserves that behavior.
fn operation_option_tokens(value: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start = None;
    let mut interpolation_depth = 0usize;
    let mut chars = value.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if interpolation_depth > 0 {
            match character {
                '{' => interpolation_depth += 1,
                '}' => interpolation_depth -= 1,
                _ => {}
            }
            continue;
        }
        if character == '@' && chars.peek().is_some_and(|(_, next)| *next == '{') {
            start.get_or_insert(index);
            interpolation_depth = 1;
            chars.next();
            continue;
        }
        if character == ',' || character.is_ascii_whitespace() {
            if let Some(token_start) = start.take()
                && token_start < index
            {
                tokens.push(&value[token_start..index]);
            }
        } else {
            start.get_or_insert(index);
        }
    }
    if let Some(token_start) = start
        && token_start < value.len()
    {
        tokens.push(&value[token_start..]);
    }
    tokens
}

/// True if `expected` is present as a literal token. Used from other rule
/// modules (e.g. concurrency) that only care about presence, not shape.
pub(super) fn operation_option_enabled(options: &str, expected: &str) -> bool {
    options
        .split(|character: char| character == ',' || character.is_ascii_whitespace())
        .any(|option| option == expected)
}
