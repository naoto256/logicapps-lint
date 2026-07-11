//! Shape validators for the HTTP-family connector actions:
//! `Http`, `HttpWebhook`, `ApiConnection`, `ApiConnectionWebhook`,
//! `ApiManagement`, and `Function`. The cross-family plumbing (HTTP inputs
//! shape, retry policy, webhook subscribe/unsubscribe, endpoint URI) lives in
//! the sibling `super::super::http` module so trigger validators in
//! `super::super::triggers::http` can reuse it without reaching into the
//! actions subtree.

use super::super::http::{
    HTTP_ENDPOINT_METHODS, REQUEST_METHODS, RetryPolicyIntervalBounds, WebhookOperationOptions,
    WebhookOperationString, validate_api_management_inputs, validate_http_inputs,
    validate_webhook_operation,
};
use super::super::materialized::arm_optional_property_absent;
use super::*;

pub(in crate::check::shape) const ACCESS_KEY_TYPES: &[&str] = &["Primary", "Secondary"];

/// Validate an `Http` action: `inputs.method` (endpoint verb) plus `inputs.uri`,
/// then the shared HTTP inputs surface (headers, queries, authentication,
/// retryPolicy). The registry has already handled ARM opaque `inputs`.
pub(in crate::check::shape) fn validate_http_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    let inputs_pointer = pointer_join(action_pointer, "inputs");
    require_typed_field(
        inputs,
        &inputs_pointer,
        "method",
        "Http inputs.method must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    require_typed_field(
        inputs,
        &inputs_pointer,
        "uri",
        "Http inputs.uri must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    validate_optional_string_enum(
        inputs,
        &inputs_pointer,
        "method",
        "Http inputs.method",
        HTTP_ENDPOINT_METHODS,
        file,
        diagnostics,
    );
    validate_http_endpoint_uri(
        inputs,
        &inputs_pointer,
        "uri",
        "Http inputs.uri",
        file,
        diagnostics,
    );
    validate_http_inputs(
        inputs,
        &inputs_pointer,
        "Http inputs",
        RetryPolicyIntervalBounds::for_workflow(workflow),
        file,
        diagnostics,
    );
}

/// Validate an `ApiConnection` action: connector-hosted call keyed by
/// `inputs.host.connection` + `inputs.path`. `method` is optional (many
/// connector operations imply their verb) and matched case-insensitively.
pub(in crate::check::shape) fn validate_api_connection_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    let inputs_pointer = pointer_join(action_pointer, "inputs");
    require_object_field(inputs, &inputs_pointer, "host", file, diagnostics);
    validate_api_connection_host(inputs, &inputs_pointer, file, diagnostics);
    validate_optional_string_enum_ignore_case(
        inputs,
        &inputs_pointer,
        "method",
        "ApiConnection inputs.method",
        HTTP_ENDPOINT_METHODS,
        file,
        diagnostics,
    );
    require_typed_field(
        inputs,
        &inputs_pointer,
        "path",
        "ApiConnection inputs.path must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    validate_optional_string_enum(
        inputs,
        &inputs_pointer,
        "accessKeyType",
        "ApiConnection inputs.accessKeyType",
        ACCESS_KEY_TYPES,
        file,
        diagnostics,
    );
    validate_http_inputs(
        inputs,
        &inputs_pointer,
        "ApiConnection inputs",
        RetryPolicyIntervalBounds::for_workflow(workflow),
        file,
        diagnostics,
    );
}

/// Validate an `ApiConnectionWebhook` action. Two authoring styles coexist:
/// explicit `subscribe`/`unsubscribe` operation objects, or a flat
/// host/path/method form like `ApiConnection` — dispatch is by presence of
/// `subscribe`/`unsubscribe`.
pub(in crate::check::shape) fn validate_api_connection_webhook_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    let inputs_pointer = pointer_join(action_pointer, "inputs");
    if get(inputs, "subscribe").is_some() || get(inputs, "unsubscribe").is_some() {
        // ApiConnectionWebhook appears in two shapes: explicit subscribe/
        // unsubscribe operations, or connector host/path/method inputs.
        // In the operation-object form, string shorthand for the operation is
        // not accepted (unlike `HttpWebhook` where a URL string is allowed).
        let operation_options = WebhookOperationOptions {
            string_operation: WebhookOperationString::Disallow,
            retry_bounds: RetryPolicyIntervalBounds::for_workflow(workflow),
        };
        validate_webhook_operation(
            inputs,
            &inputs_pointer,
            "subscribe",
            true,
            operation_options,
            file,
            diagnostics,
        );
        validate_webhook_operation(
            inputs,
            &inputs_pointer,
            "unsubscribe",
            false,
            operation_options,
            file,
            diagnostics,
        );
        validate_webhook_operation_method_when_present(
            inputs,
            &inputs_pointer,
            "unsubscribe",
            file,
            diagnostics,
        );
        validate_optional_string_enum(
            inputs,
            &inputs_pointer,
            "accessKeyType",
            "ApiConnectionWebhook inputs.accessKeyType",
            ACCESS_KEY_TYPES,
            file,
            diagnostics,
        );
        return;
    }
    require_object_field(inputs, &inputs_pointer, "host", file, diagnostics);
    validate_api_connection_host(inputs, &inputs_pointer, file, diagnostics);
    validate_optional_string_enum(
        inputs,
        &inputs_pointer,
        "method",
        "ApiConnectionWebhook inputs.method",
        REQUEST_METHODS,
        file,
        diagnostics,
    );
    require_typed_field(
        inputs,
        &inputs_pointer,
        "path",
        "ApiConnectionWebhook inputs.path must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    validate_optional_string_enum(
        inputs,
        &inputs_pointer,
        "accessKeyType",
        "ApiConnectionWebhook inputs.accessKeyType",
        ACCESS_KEY_TYPES,
        file,
        diagnostics,
    );
    validate_http_inputs(
        inputs,
        &inputs_pointer,
        "ApiConnectionWebhook inputs",
        RetryPolicyIntervalBounds::for_workflow(workflow),
        file,
        diagnostics,
    );
}

/// Validate a `Function` action. The target can be identified by a raw `uri`
/// or by ARM resource references (`function`/`functionApp`) — at least one
/// must resolve. In Standard workflows, `ManagedServiceIdentity` auth is
/// rejected because the Function host uses its own key/MI plumbing there.
pub(in crate::check::shape) fn validate_function_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    // Function actions can point either at a raw URI or ARM-style resource
    // references. The latter are shallow-checked so dynamic ARM fields still work.
    let inputs_pointer = pointer_join(action_pointer, "inputs");
    let uri_present =
        get(inputs, "uri").is_some_and(|value| !arm_optional_property_absent(file, value));
    let function_present =
        get(inputs, "function").is_some_and(|value| !arm_optional_property_absent(file, value));
    let function_app_present =
        get(inputs, "functionApp").is_some_and(|value| !arm_optional_property_absent(file, value));
    if !uri_present && !function_present && !function_app_present {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(&inputs_pointer, "function"),
            Some(span(inputs)),
            "Function inputs must define uri, function, or functionApp",
        ));
    }
    if let Some(uri) = get(inputs, "uri")
        && !arm_optional_property_absent(file, uri)
        && as_string(uri).is_none()
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(&inputs_pointer, "uri"),
            Some(span(uri)),
            "Function inputs.uri must be a string",
        ));
    }
    validate_optional_string_enum(
        inputs,
        &inputs_pointer,
        "method",
        "Function inputs.method",
        HTTP_ENDPOINT_METHODS,
        file,
        diagnostics,
    );
    validate_http_inputs(
        inputs,
        &inputs_pointer,
        "Function inputs",
        RetryPolicyIntervalBounds::for_workflow(workflow),
        file,
        diagnostics,
    );
    validate_function_standard_authentication(inputs, &inputs_pointer, file, workflow, diagnostics);
    validate_optional_resource_reference(
        inputs,
        &inputs_pointer,
        "function",
        "Function inputs.function",
        file,
        diagnostics,
    );
    validate_optional_resource_reference(
        inputs,
        &inputs_pointer,
        "functionApp",
        "Function inputs.functionApp",
        file,
        diagnostics,
    );
}

fn validate_function_standard_authentication(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !workflow.is_standard() {
        return;
    }
    let Some(authentication) = get(inputs, "authentication") else {
        return;
    };
    if arm_optional_property_absent(file, authentication)
        || is_opaque_arm_expression(file, authentication)
    {
        return;
    }
    let Some(auth_type) = get(authentication, "type").and_then(as_string) else {
        return;
    };
    if auth_type.eq_ignore_ascii_case("ManagedServiceIdentity") {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(&pointer_join(inputs_pointer, "authentication"), "type"),
            get(authentication, "type").map(span),
            "Function inputs.authentication.type 'ManagedServiceIdentity' is not supported in Standard workflows",
        ));
    }
}

/// Validate the shared `inputs.host` shape of ApiConnection-family actions
/// and triggers. `host.connection` must identify the connection by at least
/// one of `name`, `id`, or `referenceName`; ARM opaque expressions short-
/// circuit the check since the value is materialized at deployment time.
pub(in crate::check::shape) fn validate_api_connection_host(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(host) = get(inputs, "host") else {
        return;
    };
    if is_opaque_arm_expression(file, host) {
        return;
    }
    let Some(_host_object) = as_object(host) else {
        return;
    };
    let host_pointer = pointer_join(inputs_pointer, "host");
    let Some(connection) = get(host, "connection") else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(&host_pointer, "connection"),
            Some(span(host)),
            "ApiConnection inputs.host is missing required object field 'connection'",
        ));
        return;
    };
    if is_opaque_arm_expression(file, connection) {
        return;
    }
    let Some(_connection_object) = as_object(connection) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(&host_pointer, "connection"),
            Some(span(connection)),
            "ApiConnection inputs.host.connection must be an object",
        ));
        return;
    };
    let connection_pointer = pointer_join(&host_pointer, "connection");
    if get(connection, "name").is_none()
        && get(connection, "referenceName").is_none()
        && get(connection, "id").is_none()
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(&connection_pointer, "name"),
            Some(span(connection)),
            "ApiConnection inputs.host.connection must define name, id, or referenceName",
        ));
    }
    if let Some(name) = get(connection, "name")
        && !is_opaque_arm_expression(file, name)
        && as_string(name).is_none()
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(&connection_pointer, "name"),
            Some(span(name)),
            "ApiConnection inputs.host.connection.name must be a string",
        ));
    }
    if let Some(reference_name) = get(connection, "referenceName")
        && !is_opaque_arm_expression(file, reference_name)
        && as_string(reference_name).is_none()
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(&connection_pointer, "referenceName"),
            Some(span(reference_name)),
            "ApiConnection inputs.host.connection.referenceName must be a string",
        ));
    }
    if let Some(id) = get(connection, "id")
        && !is_opaque_arm_expression(file, id)
        && as_string(id).is_none()
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(&connection_pointer, "id"),
            Some(span(id)),
            "ApiConnection inputs.host.connection.id must be a string",
        ));
    }
}

/// Validate an `ApiManagement` action; delegates to
/// [`validate_api_management_inputs`] so the same shape can be reused by the
/// `ApiManagement` trigger.
pub(in crate::check::shape) fn validate_api_management_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    validate_api_management_inputs(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        RetryPolicyIntervalBounds::for_workflow(workflow),
        file,
        diagnostics,
    );
}

fn validate_webhook_operation_method_when_present(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    field: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(operation) = get(inputs, field) else {
        return;
    };
    if is_opaque_arm_expression(file, operation) || as_string(operation).is_some() {
        return;
    }
    if as_object(operation).is_some() && get(operation, "method").is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(&pointer_join(inputs_pointer, field), "method"),
            Some(span(operation)),
            "webhook operation is missing required field 'method'",
        ));
    }
}

/// Validate an `HttpWebhook` action. Unlike `ApiConnectionWebhook`, the
/// operations may be authored either as an object or as a bare URL string.
pub(in crate::check::shape) fn validate_http_webhook_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    let inputs_pointer = pointer_join(action_pointer, "inputs");
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
