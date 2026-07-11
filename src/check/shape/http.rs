//! Cross-family HTTP shape helpers shared across action and trigger validators.
//!
//! This module owns the pieces of the HTTP surface that are not tied to any
//! single action or trigger kind: the verb sets, retry-policy plumbing, the
//! shared `validate_http_inputs`/`validate_api_management_inputs` shapes, and
//! the webhook `subscribe`/`unsubscribe` operation checks. Action-specific
//! validators (the `validate_*_action` entry points registered in
//! `ACTION_SPECS`) still live in `actions::connectors`, and trigger-specific
//! validators live in `triggers::http`; both call into this module rather than
//! reaching into each other.

use super::materialized::arm_optional_property_absent;
use super::*;

// Full HTTP verb set accepted by connector inputs. `HTTP_ENDPOINT_METHODS` is
// the stricter subset the Logic Apps runtime actually invokes over the wire
// (no HEAD/OPTIONS/TRACE) — used for `Http`, `Function`, and `ApiConnection`
// action inputs.
pub(in crate::check::shape) const REQUEST_METHODS: &[&str] = &[
    "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE",
];
pub(in crate::check::shape) const HTTP_ENDPOINT_METHODS: &[&str] =
    &["DELETE", "GET", "PATCH", "POST", "PUT"];

const HTTP_AUTHENTICATION_TYPES: &[&str] = &[
    "ActiveDirectoryOAuth",
    "Basic",
    "ClientCertificate",
    "ManagedServiceIdentity",
    "None",
    "Raw",
];
const HTTP_RETRY_POLICY_TYPES: &[&str] = &["Default", "Exponential", "Fixed", "None"];

/// Validate the shared `inputs` surface used by every HTTP-family action or
/// trigger: `ApiManagement` inputs (`api`/`pathTemplate`/`method`/
/// `subscriptionKey`) plus the general HTTP inputs (headers, queries, auth,
/// retryPolicy). `retry_bounds` narrows the retry interval range based on
/// stateful vs stateless host semantics.
pub(in crate::check::shape) fn validate_api_management_inputs(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    retry_bounds: RetryPolicyIntervalBounds,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    require_object_field(inputs, inputs_pointer, "api", file, diagnostics);
    if let Some(api) = get(inputs, "api")
        && as_object(api).is_some()
    {
        let api_pointer = pointer_join(inputs_pointer, "api");
        for field in ["id", "name", "type"] {
            validate_optional_string_field(
                api,
                &api_pointer,
                field,
                &format!("ApiManagement inputs.api.{field}"),
                file,
                diagnostics,
            );
        }
    }
    require_typed_field(
        inputs,
        inputs_pointer,
        "pathTemplate",
        "ApiManagement inputs.pathTemplate must be present",
        file,
        diagnostics,
        |_| true,
    );
    validate_optional_string_enum(
        inputs,
        inputs_pointer,
        "method",
        "ApiManagement inputs.method",
        REQUEST_METHODS,
        file,
        diagnostics,
    );
    validate_optional_string_field(
        inputs,
        inputs_pointer,
        "subscriptionKey",
        "ApiManagement inputs.subscriptionKey",
        file,
        diagnostics,
    );
    validate_http_inputs(
        inputs,
        inputs_pointer,
        "ApiManagement inputs",
        retry_bounds,
        file,
        diagnostics,
    );
}

/// Shared HTTP-family inputs checks: headers, queries, cookie,
/// operationOptions, authentication, retryPolicy. Reused by every action or
/// trigger that speaks HTTP (Http, ApiConnection*, ApiManagement, Function,
/// Workflow, HttpWebhook operations). `retry_bounds` narrows the allowed
/// retry interval range based on stateful vs stateless host semantics.
pub(in crate::check::shape) fn validate_http_inputs(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    label: &str,
    retry_bounds: RetryPolicyIntervalBounds,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_optional_object_or_string_field(
        inputs,
        inputs_pointer,
        "headers",
        &format!("{label}.headers"),
        file,
        diagnostics,
    );
    validate_optional_object_or_wdl_expression_field(
        inputs,
        inputs_pointer,
        "queries",
        &format!("{label}.queries"),
        file,
        diagnostics,
    );
    validate_optional_string_field(
        inputs,
        inputs_pointer,
        "cookie",
        &format!("{label}.cookie"),
        file,
        diagnostics,
    );
    validate_optional_string_field(
        inputs,
        inputs_pointer,
        "operationOptions",
        &format!("{label}.operationOptions"),
        file,
        diagnostics,
    );
    super::operation_options::validate_operation_options_literal_values(
        inputs,
        inputs_pointer,
        "action",
        file,
        diagnostics,
    );
    validate_http_authentication(inputs, inputs_pointer, label, file, diagnostics);
    validate_http_retry_policy(
        inputs,
        inputs_pointer,
        label,
        retry_bounds,
        file,
        diagnostics,
    );
}

/// Stateful hosts persist retry state and allow long intervals (5s..24h);
/// stateless hosts must complete within a request lifetime, so retries are
/// capped at 1s..60s.
#[derive(Clone, Copy)]
pub(in crate::check::shape) enum RetryPolicyIntervalBounds {
    Stateful,
    Stateless,
}

impl RetryPolicyIntervalBounds {
    pub(in crate::check::shape) fn for_workflow(workflow: &Workflow<'_>) -> Self {
        if workflow.is_stateless() {
            Self::Stateless
        } else {
            Self::Stateful
        }
    }

    fn range_seconds(self) -> (f64, f64) {
        match self {
            Self::Stateful => (5.0, 86_400.0),
            Self::Stateless => (1.0, 60.0),
        }
    }
}

fn validate_optional_object_or_wdl_expression_field(
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
    if arm_optional_property_absent(file, value) || is_opaque_arm_expression(file, value) {
        return;
    }
    if let Some(text) = as_string(value)
        && is_wdl_full_expression_string(text)
    {
        return;
    }
    if as_object(value).is_some() {
        validate_scalar_object_values(
            value,
            &pointer_join(object_pointer, field),
            label,
            file,
            diagnostics,
        );
    } else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} must be an object"),
        ));
    }
}

fn is_wdl_full_expression_string(value: &str) -> bool {
    value.starts_with('@') && !value.starts_with("@@") && !value.starts_with("@{")
}

// The `authentication` field is polymorphic: an object with a `type` and
// type-specific credential fields, OR a full WDL string expression that
// resolves to such an object at runtime. Non-expression strings are rejected
// because they can never be a valid literal auth object.
//
// Diagnostics raised from this function deliberately omit the source span so
// the human renderer does not print inline credential values. The JSON
// Pointer + code + message already identify the location precisely enough for
// automation and the annotate-snippets renderer alike.
fn validate_http_authentication(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(authentication) = get(inputs, "authentication") else {
        return;
    };
    if arm_optional_property_absent(file, authentication)
        || is_opaque_arm_expression(file, authentication)
    {
        return;
    }
    let authentication_pointer = pointer_join(inputs_pointer, "authentication");
    if let Some(authentication_text) = as_string(authentication) {
        if is_wdl_full_expression_string(authentication_text) {
            return;
        }
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            authentication_pointer,
            None,
            format!("{label}.authentication string value must be a WDL expression"),
        ));
        return;
    }
    let Some(authentication_object) = as_object(authentication) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            authentication_pointer,
            None,
            format!("{label}.authentication must be a string expression or object"),
        ));
        return;
    };
    validate_optional_string_enum(
        authentication,
        &authentication_pointer,
        "type",
        &format!("{label}.authentication.type"),
        HTTP_AUTHENTICATION_TYPES,
        file,
        diagnostics,
    );
    if get(authentication, "type").is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(&authentication_pointer, "type"),
            None,
            format!("{label}.authentication is missing required field 'type'"),
        ));
    }
    let credential_fields = [
        "authority",
        "audience",
        "clientId",
        "identity",
        "parameter",
        "password",
        "pfx",
        "scheme",
        "secret",
        "tenant",
        "username",
        "value",
    ];
    // `type: None` disables authentication; any additional credential-shaped
    // field is misleading and must be reported (ARM-absent fields excepted).
    if get(authentication, "type")
        .and_then(as_string)
        .is_some_and(|auth_type| auth_type.eq_ignore_ascii_case("None"))
    {
        for (field, value) in authentication_object.iter() {
            if field.as_str() == "type" || arm_optional_property_absent(file, value) {
                continue;
            }
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                pointer_join(&authentication_pointer, field),
                Some(span(value)),
                format!(
                    "{label}.authentication.{field} is not supported when authentication.type is None"
                ),
            ));
        }
        return;
    }
    if get(authentication, "type")
        .and_then(as_string)
        .is_some_and(|auth_type| auth_type.eq_ignore_ascii_case("ActiveDirectoryOAuth"))
    {
        validate_optional_string_enum_ignore_case(
            authentication,
            &authentication_pointer,
            "credentialType",
            &format!("{label}.authentication.credentialType"),
            &["Certificate", "Secret"],
            file,
            diagnostics,
        );
    }
    let required_fields = get(authentication, "type")
        .and_then(as_string)
        .map(|auth_type| required_authentication_fields(authentication, auth_type, file))
        .unwrap_or(&[]);
    for field in required_fields {
        require_authentication_string_field(
            authentication,
            &authentication_pointer,
            field,
            label,
            file,
            diagnostics,
        );
    }
    for field in credential_fields {
        if required_fields.contains(&field) {
            continue;
        }
        validate_optional_string_field(
            authentication,
            &authentication_pointer,
            field,
            &format!("{label}.authentication.{field}"),
            file,
            diagnostics,
        );
    }
}

// Required credential field set per authentication type. For AAD OAuth the
// set depends on `credentialType`: Certificate needs pfx+password, Secret
// needs `secret`; when the credentialType itself is an ARM expression we
// fall back to the intersection to avoid false positives.
fn required_authentication_fields(
    authentication: &json_spanned_value::spanned::Value,
    auth_type: &str,
    file: &JsonFile,
) -> &'static [&'static str] {
    if auth_type.eq_ignore_ascii_case("ActiveDirectoryOAuth") {
        match get(authentication, "credentialType") {
            Some(credential_type) if is_opaque_arm_expression(file, credential_type) => {
                &["tenant", "audience", "clientId"]
            }
            Some(credential_type)
                if as_string(credential_type).is_some_and(|credential_type| {
                    credential_type.eq_ignore_ascii_case("Certificate")
                }) =>
            {
                &["tenant", "audience", "clientId", "pfx", "password"]
            }
            _ => &["tenant", "audience", "clientId", "secret"],
        }
    } else if auth_type.eq_ignore_ascii_case("Basic") {
        &["username", "password"]
    } else if auth_type.eq_ignore_ascii_case("ClientCertificate") {
        &["pfx"]
    } else if auth_type.eq_ignore_ascii_case("ManagedServiceIdentity") {
        &[]
    } else if auth_type.eq_ignore_ascii_case("Raw") {
        &["value"]
    } else {
        &[]
    }
}

fn require_authentication_string_field(
    authentication: &json_spanned_value::spanned::Value,
    authentication_pointer: &str,
    field: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(authentication, field) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(authentication_pointer, field),
            None,
            format!("{label}.authentication is missing required field '{field}'"),
        ));
        return;
    };
    if !is_opaque_arm_expression(file, value) && as_string(value).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(authentication_pointer, field),
            Some(span(value)),
            format!("{label}.authentication.{field} must be a string"),
        ));
    }
}

/// Validate `inputs.retryPolicy`: `type` gates which fields are required
/// (`Fixed`/`Exponential` need `count` and `interval`), retry `count` is
/// bounded 1..=90, and interval strings must be ISO 8601 durations within
/// the `retry_bounds` range. Also enforces minimum <= maximum interval.
pub(in crate::check::shape) fn validate_http_retry_policy(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    label: &str,
    retry_bounds: RetryPolicyIntervalBounds,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(retry_policy) = get(inputs, "retryPolicy") else {
        return;
    };
    if arm_optional_property_absent(file, retry_policy)
        || is_opaque_arm_expression(file, retry_policy)
    {
        return;
    }
    let retry_pointer = pointer_join(inputs_pointer, "retryPolicy");
    if as_object(retry_policy).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            retry_pointer,
            Some(span(retry_policy)),
            format!("{label}.retryPolicy must be an object"),
        ));
        return;
    }
    let retry_type = if let Some(value) =
        get(retry_policy, "type").filter(|value| !arm_optional_property_absent(file, value))
    {
        if is_opaque_arm_expression(file, value) {
            None
        } else if let Some(text) = as_string(value) {
            let analyzed = crate::wdl::WdlStringValue::classify(text);
            if !analyzed.may_match_exact_ignore_case(HTTP_RETRY_POLICY_TYPES) {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-value",
                    &file.path,
                    pointer_join(&retry_pointer, "type"),
                    Some(span(value)),
                    format!("{label}.retryPolicy.type '{text}' is not supported"),
                ));
            }
            analyzed.literal().map(str::to_owned)
        } else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                pointer_join(&retry_pointer, "type"),
                Some(span(value)),
                format!("{label}.retryPolicy.type must be a string"),
            ));
            None
        }
    } else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(&retry_pointer, "type"),
            Some(span(retry_policy)),
            "retryPolicy is missing required field 'type'",
        ));
        None
    };
    validate_optional_integer_range(
        retry_policy,
        &retry_pointer,
        "count",
        &format!("{label}.retryPolicy.count"),
        (1, 90),
        file,
        diagnostics,
    );
    for field in ["interval", "minimumInterval", "maximumInterval"] {
        validate_optional_retry_duration_field(
            retry_policy,
            &retry_pointer,
            field,
            &format!("{label}.retryPolicy.{field}"),
            retry_bounds,
            file,
            diagnostics,
        );
    }
    validate_retry_minimum_not_greater_than_maximum(
        retry_policy,
        &retry_pointer,
        label,
        file,
        diagnostics,
    );
    if retry_type.is_some_and(|policy_type| {
        policy_type.eq_ignore_ascii_case("Fixed") || policy_type.eq_ignore_ascii_case("Exponential")
    }) {
        for field in ["count", "interval"] {
            if get(retry_policy, field)
                .is_none_or(|value| arm_optional_property_absent(file, value))
            {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-missing-field",
                    &file.path,
                    pointer_join(&retry_pointer, field),
                    Some(span(retry_policy)),
                    format!("retryPolicy is missing required field '{field}'"),
                ));
            }
        }
    }
}

fn validate_retry_minimum_not_greater_than_maximum(
    retry_policy: &json_spanned_value::spanned::Value,
    retry_pointer: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(minimum) = get(retry_policy, "minimumInterval") else {
        return;
    };
    let Some(maximum) = get(retry_policy, "maximumInterval") else {
        return;
    };
    if is_opaque_arm_expression(file, minimum) || is_opaque_arm_expression(file, maximum) {
        return;
    }
    let Some(minimum_text) = as_string(minimum) else {
        return;
    };
    let Some(maximum_text) = as_string(maximum) else {
        return;
    };
    let minimum_value = crate::wdl::WdlStringValue::classify(minimum_text);
    let maximum_value = crate::wdl::WdlStringValue::classify(maximum_text);
    let Some(minimum_text) = minimum_value.literal() else {
        return;
    };
    let Some(maximum_text) = maximum_value.literal() else {
        return;
    };
    let Some(minimum_seconds) = iso8601_duration_seconds(minimum_text) else {
        return;
    };
    let Some(maximum_seconds) = iso8601_duration_seconds(maximum_text) else {
        return;
    };
    if minimum_seconds > maximum_seconds {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(retry_pointer, "minimumInterval"),
            Some(span(minimum)),
            format!(
                "{label}.retryPolicy.minimumInterval must be less than or equal to maximumInterval"
            ),
        ));
    }
}

fn validate_optional_retry_duration_field(
    retry_policy: &json_spanned_value::spanned::Value,
    retry_pointer: &str,
    field: &str,
    label: &str,
    retry_bounds: RetryPolicyIntervalBounds,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(retry_policy, field) else {
        return;
    };
    if arm_optional_property_absent(file, value) || is_opaque_arm_expression(file, value) {
        return;
    }
    match as_string(value) {
        Some(text) if !wdl_string_may_be_iso8601_duration(text) => {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                pointer_join(retry_pointer, field),
                Some(span(value)),
                format!("{label} must be an ISO 8601 duration"),
            ))
        }
        Some(text)
            if crate::wdl::WdlStringValue::classify(text)
                .literal()
                .is_none() => {}
        Some(text) if retry_duration_in_range(text, retry_bounds).is_some_and(|valid| valid) => {}
        Some(text) if is_iso8601_duration(text) => diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(retry_pointer, field),
            Some(span(value)),
            format!("{label} must be within the supported retry interval range"),
        )),
        Some(_) => diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(retry_pointer, field),
            Some(span(value)),
            format!("{label} must be an ISO 8601 duration"),
        )),
        None => diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(retry_pointer, field),
            Some(span(value)),
            format!("{label} must be a string"),
        )),
    }
}

fn retry_duration_in_range(value: &str, retry_bounds: RetryPolicyIntervalBounds) -> Option<bool> {
    let seconds = iso8601_duration_seconds(value)?;
    let (min, max) = retry_bounds.range_seconds();
    Some(seconds >= min && seconds <= max)
}

// Best-effort ISO 8601 duration parser: converts to seconds so retry bounds
// can be numerically compared. Calendar months/years are rejected because a
// retry interval must be a fixed duration.
fn iso8601_duration_seconds(value: &str) -> Option<f64> {
    let rest = value.strip_prefix('P')?;
    if rest.is_empty() {
        return None;
    }

    let mut total = 0.0;
    let mut has_component = false;
    let mut in_time = false;
    let mut chars = rest.chars().peekable();
    while let Some(ch) = chars.peek().copied() {
        if ch == 'T' {
            if in_time {
                return None;
            }
            in_time = true;
            chars.next();
            continue;
        }

        let mut numeric = String::new();
        while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
            numeric.push(chars.next()?);
        }
        if chars.peek() == Some(&'.') || chars.peek() == Some(&',') {
            numeric.push('.');
            chars.next();
            let mut fractional_digit = false;
            while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
                fractional_digit = true;
                numeric.push(chars.next()?);
            }
            if !fractional_digit {
                return None;
            }
        }
        if numeric.is_empty() {
            return None;
        }
        let amount = numeric.parse::<f64>().ok()?;
        let unit = chars.next()?;
        let factor = match (in_time, unit) {
            (true, 'H') => 3_600.0,
            (true, 'M') => 60.0,
            (true, 'S') => 1.0,
            (false, 'W') => 604_800.0,
            (false, 'D') => 86_400.0,
            // Calendar months and years are not fixed retry interval durations.
            (false, 'M' | 'Y') => return None,
            _ => return None,
        };
        total += amount * factor;
        has_component = true;
    }

    has_component.then_some(total)
}

#[derive(Clone, Copy)]
pub(in crate::check::shape) enum WebhookOperationString {
    Allow,
    Disallow,
}

#[derive(Clone, Copy)]
pub(in crate::check::shape) struct WebhookOperationOptions {
    pub string_operation: WebhookOperationString,
    pub retry_bounds: RetryPolicyIntervalBounds,
}

/// Validate one webhook operation (`subscribe`/`unsubscribe`).
/// `required=true` demands the field and full HTTP inputs; `required=false`
/// permits omission and treats the URL as optional. `string_operation`
/// selects whether a bare URL string is a legal shorthand for the object.
pub(in crate::check::shape) fn validate_webhook_operation(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    field: &str,
    required: bool,
    options: WebhookOperationOptions,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(operation) = get(inputs, field) else {
        if required {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-missing-field",
                &file.path,
                pointer_join(inputs_pointer, field),
                Some(span(inputs)),
                format!("object is missing required field '{field}'"),
            ));
        }
        return;
    };
    let operation_pointer = pointer_join(inputs_pointer, field);
    if is_opaque_arm_expression(file, operation) {
        // A deployment expression can supply the whole operation object.
        return;
    }
    if as_string(operation).is_some() {
        if matches!(options.string_operation, WebhookOperationString::Allow) {
            return;
        }
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            operation_pointer,
            Some(span(operation)),
            format!("webhook {field} must be an object"),
        ));
        return;
    }
    if as_object(operation).is_none() {
        let expected = if matches!(options.string_operation, WebhookOperationString::Allow) {
            "object or string"
        } else {
            "object"
        };
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            operation_pointer,
            Some(span(operation)),
            format!("webhook {field} must be an {expected}"),
        ));
        return;
    }
    if required {
        validate_required_string_enum(
            operation,
            &operation_pointer,
            "method",
            "webhook operation method",
            REQUEST_METHODS,
            file,
            diagnostics,
        );
        validate_webhook_operation_url(operation, &operation_pointer, field, file, diagnostics);
    } else {
        validate_optional_string_enum(
            operation,
            &operation_pointer,
            "method",
            "webhook operation method",
            REQUEST_METHODS,
            file,
            diagnostics,
        );
        validate_optional_webhook_operation_url(operation, &operation_pointer, file, diagnostics);
    }
    validate_http_inputs(
        operation,
        &operation_pointer,
        &format!("webhook {field}"),
        options.retry_bounds,
        file,
        diagnostics,
    );
}

fn validate_optional_webhook_operation_url(
    operation: &json_spanned_value::spanned::Value,
    operation_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if get(operation, "uri").is_some() {
        require_typed_field(
            operation,
            operation_pointer,
            "uri",
            "webhook operation uri must be a string",
            file,
            diagnostics,
            |value| as_string(value).is_some(),
        );
        validate_http_endpoint_uri(
            operation,
            operation_pointer,
            "uri",
            "webhook operation uri",
            file,
            diagnostics,
        );
    }
    if get(operation, "url").is_some() {
        require_typed_field(
            operation,
            operation_pointer,
            "url",
            "webhook operation url must be a string",
            file,
            diagnostics,
            |value| as_string(value).is_some(),
        );
        validate_http_endpoint_uri(
            operation,
            operation_pointer,
            "url",
            "webhook operation url",
            file,
            diagnostics,
        );
    }
}

/// Require the URL of a webhook operation. `subscribe` must use `uri`;
/// `unsubscribe` also accepts the legacy `url` spelling.
pub(in crate::check::shape) fn validate_webhook_operation_url(
    operation: &json_spanned_value::spanned::Value,
    operation_pointer: &str,
    field: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if get(operation, "uri").is_some() {
        require_typed_field(
            operation,
            operation_pointer,
            "uri",
            "webhook operation uri must be a string",
            file,
            diagnostics,
            |value| as_string(value).is_some(),
        );
        validate_http_endpoint_uri(
            operation,
            operation_pointer,
            "uri",
            "webhook operation uri",
            file,
            diagnostics,
        );
        return;
    }
    if field.eq_ignore_ascii_case("unsubscribe") && get(operation, "url").is_some() {
        require_typed_field(
            operation,
            operation_pointer,
            "url",
            "webhook operation url must be a string",
            file,
            diagnostics,
            |value| as_string(value).is_some(),
        );
        validate_http_endpoint_uri(
            operation,
            operation_pointer,
            "url",
            "webhook operation url",
            file,
            diagnostics,
        );
        return;
    }
    let expected = if field.eq_ignore_ascii_case("unsubscribe") {
        "uri' or 'url"
    } else {
        "uri"
    };
    diagnostics.push(Diagnostic::error(
        "workflow-shape-missing-field",
        &file.path,
        pointer_join(operation_pointer, "uri"),
        Some(span(operation)),
        format!("object is missing required field '{expected}'"),
    ));
}
