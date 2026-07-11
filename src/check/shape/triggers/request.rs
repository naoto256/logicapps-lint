//! Shape validator for the `Request` trigger (a.k.a. manual HTTP trigger).
//! The trigger accepts inbound HTTP calls and optionally proxies through an
//! Azure `host.api` binding for connector-hosted request handlers.

use super::super::common as shape_common;
use super::super::materialized::arm_optional_property_absent;
use super::super::*;

use super::super::http::REQUEST_METHODS;

const REQUEST_TRIGGER_KINDS: &[&str] = &[
    "Alert",
    "AzureMonitorAlert",
    "Button",
    "EventGrid",
    "Geofence",
    "Http",
    "PowerApp",
    "SecurityCenterAlert",
];

/// Validate a `Request` trigger. When `kind` is one of the well-known
/// operation kinds but not one of the kinds the Request trigger accepts, we
/// flag it — a mis-set `kind` silently changes runtime dispatch. `inputs`
/// is optional (a plain HTTP receiver has no shape); when present, its
/// method must be a recognized verb and the optional connector host binding
/// must be well-formed.
pub(in crate::check::shape) fn validate_request_trigger(
    trigger: &json_spanned_value::spanned::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some(kind) = get(trigger, "kind")
        && !is_opaque_arm_expression(file, kind)
        && let Some(kind_text) = as_string(kind)
        && string_in_exact(kind_text, shape_common::COMMON_OPERATION_KINDS)
        && !string_in_exact(kind_text, REQUEST_TRIGGER_KINDS)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(trigger_pointer, "kind"),
            Some(span(kind)),
            format!("Request trigger kind '{kind_text}' is not supported"),
        ));
    }
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
            "trigger field 'inputs' must be an object",
        ));
        return;
    }
    validate_optional_string_enum(
        inputs,
        &pointer_join(trigger_pointer, "inputs"),
        "method",
        "Request trigger inputs.method",
        REQUEST_METHODS,
        file,
        diagnostics,
    );
    validate_optional_object_field(
        inputs,
        &pointer_join(trigger_pointer, "inputs"),
        "host",
        "Request trigger inputs.host",
        file,
        diagnostics,
    );
    validate_request_host_api(
        inputs,
        &pointer_join(trigger_pointer, "inputs"),
        file,
        diagnostics,
    );
    validate_optional_string_field(
        inputs,
        &pointer_join(trigger_pointer, "inputs"),
        "operationId",
        "Request trigger inputs.operationId",
        file,
        diagnostics,
    );
    validate_optional_object_field(
        inputs,
        &pointer_join(trigger_pointer, "inputs"),
        "parameters",
        "Request trigger inputs.parameters",
        file,
        diagnostics,
    );
    validate_optional_string_field(
        inputs,
        &pointer_join(trigger_pointer, "inputs"),
        "relativePath",
        "Request trigger inputs.relativePath",
        file,
        diagnostics,
    );
}

fn validate_request_host_api(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(host) = get(inputs, "host") else {
        return;
    };
    if arm_optional_property_absent(file, host) || is_opaque_arm_expression(file, host) {
        return;
    }
    let Some(_) = as_object(host) else {
        return;
    };
    let host_pointer = pointer_join(inputs_pointer, "host");
    let Some(api) = get(host, "api") else {
        return;
    };
    if arm_optional_property_absent(file, api) || is_opaque_arm_expression(file, api) {
        return;
    }
    let api_pointer = pointer_join(&host_pointer, "api");
    if as_object(api).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            api_pointer,
            Some(span(api)),
            "Request trigger inputs.host.api must be an object",
        ));
        return;
    }
    validate_optional_string_field(
        api,
        &api_pointer,
        "runtimeUrl",
        "Request trigger inputs.host.api.runtimeUrl",
        file,
        diagnostics,
    );
    validate_uri(
        api,
        &api_pointer,
        "runtimeUrl",
        "Request trigger inputs.host.api.runtimeUrl",
        file,
        diagnostics,
    );
}
