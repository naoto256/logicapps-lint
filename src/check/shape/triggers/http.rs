//! Shape validators for the HTTP-family trigger types: `Http`,
//! `SlidingWindow`, `HttpWebhook`, `ApiConnection`, `ApiConnectionWebhook`,
//! and `ApiManagement`. All poll- or subscribe-style triggers layer a
//! recurrence envelope over the shared HTTP inputs from the actions module.

use super::super::actions::connectors::{ACCESS_KEY_TYPES, validate_api_connection_host};
use super::super::http::{
    HTTP_ENDPOINT_METHODS, REQUEST_METHODS, RetryPolicyIntervalBounds, WebhookOperationOptions,
    WebhookOperationString, validate_api_management_inputs, validate_http_inputs,
    validate_webhook_operation,
};
use super::super::materialized::arm_optional_property_absent;
use super::super::*;
use super::recurrence::validate_recurrence_trigger;

/// Validate an `Http` polling trigger. Reuses the action-side HTTP inputs
/// shape and layers the recurrence envelope on top. Retry bounds are always
/// Stateful — polling triggers only run in stateful hosts.
pub(in crate::check::shape) fn validate_http_trigger(
    trigger: &json_spanned_value::spanned::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_recurrence_trigger(trigger, trigger_pointer, file, diagnostics);
    let Some(inputs) = required_trigger_inputs_object(trigger, trigger_pointer, file, diagnostics)
    else {
        return;
    };
    let inputs_pointer = pointer_join(trigger_pointer, "inputs");
    require_typed_field(
        inputs,
        &inputs_pointer,
        "method",
        "Http trigger inputs.method must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    require_typed_field(
        inputs,
        &inputs_pointer,
        "uri",
        "Http trigger inputs.uri must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    validate_http_endpoint_uri(
        inputs,
        &inputs_pointer,
        "uri",
        "Http trigger inputs.uri",
        file,
        diagnostics,
    );
    validate_optional_string_enum(
        inputs,
        &inputs_pointer,
        "method",
        "Http trigger inputs.method",
        REQUEST_METHODS,
        file,
        diagnostics,
    );
    validate_http_inputs(
        inputs,
        &inputs_pointer,
        "Http trigger inputs",
        RetryPolicyIntervalBounds::Stateful,
        file,
        diagnostics,
    );
}

/// Validate a `SlidingWindow` trigger: identical recurrence shape to
/// `Recurrence` with an added `inputs.delay` ISO 8601 duration that shifts
/// the window boundary by a fixed offset.
pub(in crate::check::shape) fn validate_sliding_window_trigger(
    trigger: &json_spanned_value::spanned::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_recurrence_trigger(trigger, trigger_pointer, file, diagnostics);
    let Some(inputs) = get(trigger, "inputs") else {
        return;
    };
    if arm_optional_property_absent(file, inputs) || is_opaque_arm_expression(file, inputs) {
        return;
    }
    if as_object(inputs).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(trigger_pointer, "inputs"),
            Some(span(inputs)),
            "SlidingWindow trigger inputs must be an object",
        ));
        return;
    }
    validate_optional_string_field(
        inputs,
        &pointer_join(trigger_pointer, "inputs"),
        "delay",
        "SlidingWindow trigger inputs.delay",
        file,
        diagnostics,
    );
    validate_optional_duration_field(
        inputs,
        &pointer_join(trigger_pointer, "inputs"),
        "delay",
        "SlidingWindow trigger inputs.delay",
        file,
        diagnostics,
    );
}

/// Validate an `HttpWebhook` trigger. Same subscribe/unsubscribe shape as
/// the `HttpWebhook` action, but scoped to the trigger inputs.
pub(in crate::check::shape) fn validate_http_webhook_trigger(
    trigger: &json_spanned_value::spanned::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_trigger_inputs_object(trigger, trigger_pointer, file, diagnostics)
    else {
        return;
    };
    let inputs_pointer = pointer_join(trigger_pointer, "inputs");
    validate_optional_string_enum(
        inputs,
        &inputs_pointer,
        "accessKeyType",
        "HttpWebhook inputs.accessKeyType",
        ACCESS_KEY_TYPES,
        file,
        diagnostics,
    );
    validate_webhook_operation(
        inputs,
        &inputs_pointer,
        "subscribe",
        true,
        WebhookOperationOptions {
            string_operation: WebhookOperationString::Allow,
            retry_bounds: RetryPolicyIntervalBounds::for_workflow(workflow),
        },
        file,
        diagnostics,
    );
    validate_webhook_operation(
        inputs,
        &inputs_pointer,
        "unsubscribe",
        false,
        WebhookOperationOptions {
            string_operation: WebhookOperationString::Allow,
            retry_bounds: RetryPolicyIntervalBounds::for_workflow(workflow),
        },
        file,
        diagnostics,
    );
}

/// Validate `ApiConnection` and `ApiConnectionWebhook` triggers. Dispatch
/// on the `type` field: only the polling variant needs a recurrence and
/// enforces the endpoint verb set; the webhook variant is push-driven and
/// requires a `body` template plus the broader REQUEST verb set.
pub(in crate::check::shape) fn validate_api_connection_trigger(
    trigger: &json_spanned_value::spanned::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_trigger_inputs_object(trigger, trigger_pointer, file, diagnostics)
    else {
        return;
    };
    let inputs_pointer = pointer_join(trigger_pointer, "inputs");
    require_object_field(inputs, &inputs_pointer, "host", file, diagnostics);
    validate_api_connection_host(inputs, &inputs_pointer, file, diagnostics);
    require_typed_field(
        inputs,
        &inputs_pointer,
        "path",
        "ApiConnection trigger inputs.path must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    let api_connection_trigger = get(trigger, "type")
        .and_then(as_string)
        .is_some_and(|trigger_type| trigger_type.eq_ignore_ascii_case("ApiConnection"));
    if api_connection_trigger {
        validate_recurrence_trigger(trigger, trigger_pointer, file, diagnostics);
        reject_api_connection_recurrence_schedule(trigger, trigger_pointer, file, diagnostics);
    }
    validate_optional_string_enum(
        inputs,
        &inputs_pointer,
        "accessKeyType",
        "ApiConnection trigger inputs.accessKeyType",
        ACCESS_KEY_TYPES,
        file,
        diagnostics,
    );
    if api_connection_trigger {
        if get(inputs, "method").is_none_or(|value| arm_optional_property_absent(file, value)) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-missing-field",
                &file.path,
                pointer_join(&inputs_pointer, "method"),
                Some(span(inputs)),
                "object is missing required field 'method'",
            ));
        }
        validate_optional_string_enum_ignore_case(
            inputs,
            &inputs_pointer,
            "method",
            "ApiConnection trigger inputs.method",
            HTTP_ENDPOINT_METHODS,
            file,
            diagnostics,
        );
    } else {
        validate_optional_string_enum_ignore_case(
            inputs,
            &inputs_pointer,
            "method",
            "ApiConnection trigger inputs.method",
            REQUEST_METHODS,
            file,
            diagnostics,
        );
        require_field(inputs, &inputs_pointer, "body", file, diagnostics);
    }
    validate_http_inputs(
        inputs,
        &inputs_pointer,
        "ApiConnection trigger inputs",
        RetryPolicyIntervalBounds::for_workflow(workflow),
        file,
        diagnostics,
    );
}

fn validate_optional_duration_field(
    object: &json_spanned_value::spanned::Value,
    object_pointer: &str,
    field: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(object, field) else {
        return;
    };
    if is_opaque_arm_expression(file, value) {
        return;
    }
    if let Some(text) = as_string(value)
        && !wdl_string_may_be_iso8601_duration(text)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} must be an ISO 8601 duration"),
        ));
    }
}

// `ApiConnection` triggers use a simple frequency+interval recurrence; the
// `schedule` sub-object (weekDays/hours/minutes) is not honored by the
// connector runtime and must not be authored.
fn reject_api_connection_recurrence_schedule(
    trigger: &json_spanned_value::spanned::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(schedule) =
        get(trigger, "recurrence").and_then(|recurrence| get(recurrence, "schedule"))
    else {
        return;
    };
    if arm_optional_property_absent(file, schedule) || is_opaque_arm_expression(file, schedule) {
        return;
    }
    diagnostics.push(Diagnostic::error(
        "workflow-shape-invalid-context",
        &file.path,
        pointer_join(&pointer_join(trigger_pointer, "recurrence"), "schedule"),
        Some(span(schedule)),
        "ApiConnection trigger recurrence.schedule is not supported",
    ));
}

/// Validate an `ApiManagement` trigger. Delegates to the shared APIM inputs
/// shape used by the action; always Stateful retry bounds.
pub(in crate::check::shape) fn validate_api_management_trigger(
    trigger: &json_spanned_value::spanned::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_trigger_inputs_object(trigger, trigger_pointer, file, diagnostics)
    else {
        return;
    };
    validate_api_management_inputs(
        inputs,
        &pointer_join(trigger_pointer, "inputs"),
        RetryPolicyIntervalBounds::Stateful,
        file,
        diagnostics,
    );
}
