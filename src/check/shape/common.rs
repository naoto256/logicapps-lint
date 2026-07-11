//! Per-node checks shared by many action and trigger rule modules.
//!
//! Everything here operates on a single node (an action or a trigger) and
//! covers cross-cutting fields that the WDL schema attaches to the node
//! envelope rather than to any particular `type`: `description`,
//! `operationOptions`, `runtimeConfiguration`, `trackedProperties`, `limit`,
//! `kind`. Type-specific rules live in the per-connector modules and are
//! wired up through `registry.rs`.
//!
//! Rules skip opaque ARM expressions in-place; when a value is worth
//! re-validating after materialization, that happens in `materialized.rs`
//! and the callers there rebind the resulting diagnostics onto the ARM
//! source span so the report still points at the user's source text.

use super::materialized::arm_optional_property_absent;
use super::*;
use crate::json::to_json_value;

/// Action types whose `limit.timeout` is actually respected. Any other
/// action carrying `limit.timeout` gets an `invalid-context` diagnostic.
pub(super) const LIMIT_TIMEOUT_ACTION_TYPES: &[&str] = &[
    "ApiConnection",
    "ApiConnectionWebhook",
    "Http",
    "HttpWebhook",
    "Until",
    "Workflow",
];
/// Trigger analogue of [`LIMIT_TIMEOUT_ACTION_TYPES`].
pub(super) const LIMIT_TIMEOUT_TRIGGER_TYPES: &[&str] = &[
    "ApiConnection",
    "ApiConnectionWebhook",
    "Http",
    "HttpWebhook",
];
/// Valid values for the optional `kind` discriminator that appears on many
/// action and trigger types. Extend rather than replace — an unrecognised
/// value is a reportable error.
pub(super) const COMMON_OPERATION_KINDS: &[&str] = &[
    "AddToTime",
    "Alert",
    "ApiConnection",
    "AzureMonitorAlert",
    "Button",
    "ConvertTimeZone",
    "CurrentTime",
    "EventGrid",
    "Geofence",
    "GetFutureTime",
    "GetPastTime",
    "Http",
    "JsonToJson",
    "JsonToText",
    "PowerApp",
    "SecurityCenterAlert",
    "SubtractFromTime",
    "XmlToJson",
    "XmlToText",
];

/// Run every node-envelope check that applies to a fully typed action or
/// trigger. `label` is `"action"` or `"trigger"` and is spliced into
/// diagnostic messages verbatim.
pub(super) fn validate_common_fields(ctx: &mut ShapeCtx<'_, '_, '_>, site: &Site<'_>, label: &str) {
    let value = site.value;
    let pointer = site.pointer.as_str();
    let file = ctx.file;
    let workflow = ctx.workflow;
    let diagnostics = &mut *ctx.diagnostics;
    validate_optional_string_field(
        value,
        pointer,
        "description",
        &format!("{label} description"),
        file,
        diagnostics,
    );
    validate_optional_description_length(value, pointer, label, file, diagnostics);
    validate_optional_string_field(
        value,
        pointer,
        "operationOptions",
        &format!("{label} operationOptions"),
        file,
        diagnostics,
    );
    validate_optional_object_field(
        value,
        pointer,
        "runtimeConfiguration",
        &format!("{label} runtimeConfiguration"),
        file,
        diagnostics,
    );
    operation_options::validate_operation_options_values(
        value,
        pointer,
        label,
        file,
        workflow,
        diagnostics,
    );
    runtime::validate_runtime_configuration(
        value,
        pointer,
        label,
        file,
        workflow,
        ctx.arm_scope,
        diagnostics,
    );
    operation_options::validate_operation_options_conflicts(
        value,
        pointer,
        label,
        file,
        diagnostics,
    );
    validate_common_limit(value, pointer, label, file, diagnostics);
    validate_tracked_properties(value, pointer, label, file, diagnostics);
    if label == "trigger"
        && let Some(tracked) = get(value, "trackedProperties")
        && !arm_optional_property_absent(file, tracked)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(pointer, "trackedProperties"),
            Some(span(tracked)),
            "trigger trackedProperties is only supported on actions",
        ));
    }
    if label == "action"
        && get(value, "trackedProperties")
            .is_some_and(|tracked| !arm_optional_property_absent(file, tracked))
        && secure_data::operation_has_secure_data(file, value)
    {
        // Secure inputs/outputs intentionally block trackedProperties because
        // trackedProperties values are exported to diagnostics telemetry and
        // would defeat the secure-data guarantee.
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(pointer, "trackedProperties"),
            get(value, "trackedProperties").map(span),
            format!("{label} trackedProperties cannot be used with secure inputs or outputs"),
        ));
    }
    if let Some(kind) = get(value, "kind") {
        if arm_optional_property_absent(file, kind) || is_opaque_arm_expression(file, kind) {
        } else if let Some(kind_text) = as_string(kind) {
            if !common_kind_supported(value, label, kind_text) {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-value",
                    &file.path,
                    pointer_join(pointer, "kind"),
                    Some(span(kind)),
                    format!("{label} kind '{kind_text}' is not supported"),
                ));
            }
        } else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                pointer_join(pointer, "kind"),
                Some(span(kind)),
                format!("{label} kind must be a string"),
            ));
        }
    }
}

/// Reduced variant of [`validate_common_fields`] for nodes whose `type` is
/// dynamic (i.e. authored as an ARM/WDL expression). Type-dependent checks —
/// `operationOptions` conflicts, `limit.timeout` context, `kind` — are
/// skipped because we cannot know which type will resolve at runtime.
pub(super) fn validate_type_independent_common_fields(
    ctx: &mut ShapeCtx<'_, '_, '_>,
    site: &Site<'_>,
    label: &str,
) {
    let value = site.value;
    let pointer = site.pointer.as_str();
    let file = ctx.file;
    let workflow = ctx.workflow;
    let diagnostics = &mut *ctx.diagnostics;
    validate_optional_string_field(
        value,
        pointer,
        "description",
        &format!("{label} description"),
        file,
        diagnostics,
    );
    validate_optional_description_length(value, pointer, label, file, diagnostics);
    validate_optional_string_field(
        value,
        pointer,
        "operationOptions",
        &format!("{label} operationOptions"),
        file,
        diagnostics,
    );
    operation_options::validate_operation_options_literal_values(
        value,
        pointer,
        label,
        file,
        diagnostics,
    );
    validate_optional_object_field(
        value,
        pointer,
        "runtimeConfiguration",
        &format!("{label} runtimeConfiguration"),
        file,
        diagnostics,
    );
    runtime::validate_runtime_configuration_for_dynamic_type(
        value,
        pointer,
        label,
        file,
        workflow,
        ctx.arm_scope,
        diagnostics,
    );
    validate_tracked_properties(value, pointer, label, file, diagnostics);
    if label == "trigger"
        && let Some(tracked) = get(value, "trackedProperties")
        && !arm_optional_property_absent(file, tracked)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(pointer, "trackedProperties"),
            Some(span(tracked)),
            "trigger trackedProperties is only supported on actions",
        ));
    }
}

fn common_kind_supported(
    value: &json_spanned_value::spanned::Value,
    label: &str,
    kind: &str,
) -> bool {
    string_in_exact(kind, COMMON_OPERATION_KINDS)
        || (label == "action"
            && kind == "http"
            && get(value, "type").and_then(as_string) == Some("Response"))
}

/// Whether `value` is a Foreach action, based on its `type` field.
pub(super) fn is_foreach_action(value: &json_spanned_value::spanned::Value) -> bool {
    get(value, "type")
        .and_then(as_string)
        .is_some_and(|action_type| action_type.eq_ignore_ascii_case("Foreach"))
}

/// Whether `value.type` matches (case-insensitively) any string in `allowed`.
pub(super) fn node_type_is_one_of(
    value: &json_spanned_value::spanned::Value,
    allowed: &[&str],
) -> bool {
    get(value, "type")
        .and_then(as_string)
        .is_some_and(|node_type| {
            allowed
                .iter()
                .any(|allowed_type| node_type.eq_ignore_ascii_case(allowed_type))
        })
}

/// Enforce the 256-character node `description` limit. Silently skips opaque
/// ARM expressions — the materialize pass will re-check them.
pub(super) fn validate_optional_description_length(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(description) = get(value, "description") else {
        return;
    };
    if is_opaque_arm_expression(file, description) {
        return;
    }
    let Some(text) = as_string(description) else {
        return;
    };
    if text.chars().count() > 256 {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(pointer, "description"),
            Some(span(description)),
            format!("{label} description exceeds the 256 character limit"),
        ));
    }
}

fn validate_tracked_properties(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(tracked_properties) = get(value, "trackedProperties") else {
        return;
    };
    if arm_optional_property_absent(file, tracked_properties)
        || is_opaque_arm_expression(file, tracked_properties)
    {
        return;
    }
    let tracked_pointer = pointer_join(pointer, "trackedProperties");
    if as_object(tracked_properties).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            tracked_pointer,
            Some(span(tracked_properties)),
            format!("{label} trackedProperties must be an object"),
        ));
        return;
    }
    if to_json_value(tracked_properties)
        .and_then(|json| serde_json::to_string(&json).ok())
        .is_some_and(|text| text.chars().count() > 8000)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            tracked_pointer.clone(),
            Some(span(tracked_properties)),
            format!("{label} trackedProperties exceeds the 8000 character limit"),
        ));
    }
    if label == "action" && content_transfer::action_uses_chunked_transfer(value, file) {
        content_transfer::validate_chunked_tracked_properties(
            tracked_properties,
            &tracked_pointer,
            file,
            diagnostics,
        );
    }
}

/// Validate the node `limit` envelope: shape, `timeout` ISO 8601, and the
/// per-type context rules that gate where `limit.timeout` is even meaningful.
pub(super) fn validate_common_limit(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(limit) = get(value, "limit") else {
        return;
    };
    if arm_optional_property_absent(file, limit) {
        return;
    }
    if is_opaque_arm_expression(file, limit) {
        return;
    }
    let limit_pointer = pointer_join(pointer, "limit");
    if as_object(limit).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            limit_pointer,
            Some(span(limit)),
            format!("{label} limit must be an object"),
        ));
        return;
    }
    let mut timeout_allows_context_check =
        get(limit, "timeout").is_some_and(|timeout| !arm_optional_property_absent(file, timeout));
    if let Some(timeout) = get(limit, "timeout")
        && !arm_optional_property_absent(file, timeout)
        && !is_opaque_arm_expression(file, timeout)
    {
        match as_string(timeout) {
            Some(text) if wdl_string_may_be_iso8601_duration(text) => {}
            Some(_) => {
                timeout_allows_context_check = false;
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-value",
                    &file.path,
                    pointer_join(&limit_pointer, "timeout"),
                    Some(span(timeout)),
                    format!("{label} limit.timeout must be an ISO 8601 duration"),
                ));
            }
            None => {
                timeout_allows_context_check = false;
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-type",
                    &file.path,
                    pointer_join(&limit_pointer, "timeout"),
                    Some(span(timeout)),
                    format!("{label} limit.timeout must be a string"),
                ));
            }
        }
    }
    if label == "action"
        && timeout_allows_context_check
        && !node_type_is_one_of(value, LIMIT_TIMEOUT_ACTION_TYPES)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(&limit_pointer, "timeout"),
            get(limit, "timeout").map(span),
            "action limit.timeout is only supported on ApiConnection, ApiConnectionWebhook, Http, HttpWebhook, Until, and Workflow actions",
        ));
    } else if label == "trigger"
        && timeout_allows_context_check
        && !node_type_is_one_of(value, LIMIT_TIMEOUT_TRIGGER_TYPES)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(&limit_pointer, "timeout"),
            get(limit, "timeout").map(span),
            "trigger limit.timeout is only supported on ApiConnection, ApiConnectionWebhook, Http, and HttpWebhook triggers",
        ));
    }
}
