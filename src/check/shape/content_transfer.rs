//! `runtimeConfiguration.contentTransfer` shape checks.
//!
//! Chunked content transfer is action-only, supported on a small set of HTTP-ish
//! action types, and forbidden in Stateless workflows. When an action opts in,
//! its trackedProperties expressions may not reference the parts of the action
//! output (`statusCode`, `headers`) that chunked transfer suppresses.

use super::materialized::arm_optional_property_absent;
use super::*;

// The runtime accepts only "Chunked" today; the enum shape is kept so future
// modes drop in without a signature change.
const CONTENT_TRANSFER_MODES: &[&str] = &["Chunked"];

/// Validate `runtimeConfiguration.contentTransfer` for an action or trigger.
pub(super) fn validate_runtime_content_transfer(
    site: runtime::RuntimeSite<'_, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(content_transfer) = get(site.runtime, "contentTransfer") else {
        return;
    };
    // Opaque ARM handling: if the whole object is a template expression, skip
    // static checks; the materialized pass will re-run this rule.
    if arm_optional_property_absent(site.file, content_transfer)
        || is_opaque_arm_expression(site.file, content_transfer)
    {
        return;
    }
    let content_pointer = pointer_join(site.pointer, "contentTransfer");
    if site.label != "action" {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &site.file.path,
            content_pointer.clone(),
            Some(span(content_transfer)),
            format!(
                "{} runtimeConfiguration.contentTransfer is only supported on actions",
                site.label
            ),
        ));
    }
    if as_object(content_transfer).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &site.file.path,
            content_pointer,
            Some(span(content_transfer)),
            format!(
                "{} runtimeConfiguration.contentTransfer must be an object",
                site.label
            ),
        ));
        return;
    }
    if site.label == "action"
        && site.operation_type_known
        && !action_type_supports_content_transfer(site.operation)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &site.file.path,
            content_pointer.clone(),
            Some(span(content_transfer)),
            "action runtimeConfiguration.contentTransfer is not supported for this action type",
        ));
    }
    if site.label == "action" && site.workflow.is_stateless() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &site.file.path,
            content_pointer.clone(),
            Some(span(content_transfer)),
            "action runtimeConfiguration.contentTransfer is not supported in Stateless workflows",
        ));
    }
    // transferMode compares case-insensitively to match runtime behavior.
    validate_optional_string_enum_ignore_case(
        content_transfer,
        &content_pointer,
        "transferMode",
        &format!(
            "{} runtimeConfiguration.contentTransfer.transferMode",
            site.label
        ),
        CONTENT_TRANSFER_MODES,
        site.file,
        diagnostics,
    );
}

/// Only HTTP-shaped action types stream chunked. When `type` is missing or
/// dynamic, err on the permissive side — other rules will flag the missing type.
fn action_type_supports_content_transfer(value: &json_spanned_value::spanned::Value) -> bool {
    let Some(action_type) = get(value, "type").and_then(as_string) else {
        return true;
    };
    [
        "ApiConnection",
        "ApiConnectionWebhook",
        "Http",
        "HttpWebhook",
    ]
    .iter()
    .any(|allowed| action_type.eq_ignore_ascii_case(allowed))
}

/// True when the action's runtime configuration statically resolves to chunked
/// transfer. Used by trackedProperties validation to decide whether to walk the
/// tree looking for unavailable output references.
pub(super) fn action_uses_chunked_transfer(
    value: &json_spanned_value::spanned::Value,
    file: &JsonFile,
) -> bool {
    let Some(transfer_mode) = get(value, "runtimeConfiguration")
        .and_then(|runtime| get(runtime, "contentTransfer"))
        .and_then(|content_transfer| get(content_transfer, "transferMode"))
    else {
        return false;
    };
    if is_opaque_arm_expression(file, transfer_mode) {
        return false;
    }
    as_string(transfer_mode).is_some_and(|mode| mode.eq_ignore_ascii_case("Chunked"))
}

/// Recursively walk trackedProperties and flag WDL expressions that reference
/// `action().outputs.statusCode` / `.headers` — fields chunked mode does not
/// emit, so the reference would evaluate to null at runtime.
pub(super) fn validate_chunked_tracked_properties(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some(text) = as_string(value) {
        if chunked_tracked_property_uses_unavailable_output(text) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &file.path,
                pointer.to_owned(),
                Some(span(value)),
                "chunked action trackedProperties cannot reference unavailable statusCode or headers outputs",
            ));
        }
        return;
    }
    if let Some(object) = as_object(value) {
        for (key, child) in object.iter() {
            validate_chunked_tracked_properties(
                child,
                &pointer_join(pointer, key),
                file,
                diagnostics,
            );
        }
        return;
    }
    if let Some(array) = value.as_span_array() {
        for (index, child) in array.iter().enumerate() {
            validate_chunked_tracked_properties(
                child,
                &pointer_join(pointer, &index.to_string()),
                file,
                diagnostics,
            );
        }
    }
}

fn chunked_tracked_property_uses_unavailable_output(text: &str) -> bool {
    // Strip whitespace and lowercase so we can match by substring against the
    // handful of syntactic forms WDL accepts for property access.
    let compact: String = text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    if !compact.contains("action()") || !compact.contains("outputs") {
        return false;
    }
    ["statuscode", "headers"].iter().any(|field| {
        [
            format!(".outputs.{field}"),
            format!(".outputs['{field}']"),
            format!(".outputs?['{field}']"),
            format!("['outputs']['{field}']"),
            format!("['outputs']?['{field}']"),
            format!("?['outputs']['{field}']"),
            format!("?['outputs']?['{field}']"),
        ]
        .iter()
        .any(|pattern| compact.contains(pattern))
    })
}
