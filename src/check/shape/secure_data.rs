//! `runtimeConfiguration.secureData` shape checks.
//!
//! `secureData.properties` opts an action or trigger into masking of its
//! `inputs` and/or `outputs` in run history. The set of operation types that
//! support secure inputs and the set that support secure outputs are disjoint
//! and much narrower than the type universe, so both allowlists live below.
//! Property names compare case-insensitively — the runtime does the same.

use super::materialized::{
    arm_optional_property_absent, unresolved_arm_array_expression_from_spanned,
};
use super::*;

// Action types that cannot mask their inputs — variables, control flow, etc.
const SECURE_INPUTS_UNSUPPORTED_OPERATION_TYPES: &[&str] = &[
    "AppendToArrayVariable",
    "AppendToStringVariable",
    "DecrementVariable",
    "Foreach",
    "If",
    "IncrementVariable",
    "InitializeVariable",
    "Scope",
    "SetVariable",
    "Switch",
    "Terminate",
    "Until",
];
// Types that cannot mask outputs — includes Compose/ParseJson/Response since
// their outputs are themselves the payload the user needs to inspect.
const SECURE_OUTPUTS_UNSUPPORTED_OPERATION_TYPES: &[&str] = &[
    "AppendToArrayVariable",
    "AppendToStringVariable",
    "Compose",
    "DecrementVariable",
    "Foreach",
    "If",
    "IncrementVariable",
    "InitializeVariable",
    "ParseJson",
    "Response",
    "Scope",
    "SetVariable",
    "Switch",
    "Terminate",
    "Until",
    "Wait",
];
const SECURE_DATA_PROPERTIES: &[&str] = &["inputs", "outputs"];

/// Validate the `secureData` block: it must be an object with a required
/// `properties` array containing case-insensitive "inputs" / "outputs" strings.
/// Cross-check against the operation type's support matrix.
pub(super) fn validate_runtime_secure_data(
    site: runtime::RuntimeSite<'_, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(secure_data) = get(site.runtime, "secureData") else {
        return;
    };
    if arm_optional_property_absent(site.file, secure_data)
        || is_opaque_arm_expression(site.file, secure_data)
    {
        return;
    }
    let secure_pointer = pointer_join(site.pointer, "secureData");
    if site.label == "trigger"
        && site.operation_type_known
        && common::node_type_is_one_of(site.operation, &["Recurrence"])
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &site.file.path,
            secure_pointer.clone(),
            Some(span(secure_data)),
            "Recurrence trigger runtimeConfiguration.secureData is not supported",
        ));
    }
    if as_object(secure_data).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &site.file.path,
            secure_pointer,
            Some(span(secure_data)),
            format!(
                "{} runtimeConfiguration.secureData must be an object",
                site.label
            ),
        ));
        return;
    }
    let Some(properties) = get(secure_data, "properties") else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &site.file.path,
            pointer_join(&secure_pointer, "properties"),
            Some(span(secure_data)),
            format!(
                "{} runtimeConfiguration.secureData is missing required field 'properties'",
                site.label
            ),
        ));
        return;
    };
    if arm_optional_property_absent(site.file, properties) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &site.file.path,
            pointer_join(&secure_pointer, "properties"),
            Some(span(properties)),
            format!(
                "{} runtimeConfiguration.secureData is missing required field 'properties'",
                site.label
            ),
        ));
        return;
    }
    if unresolved_arm_array_expression_from_spanned(site.file, properties, site.arm_scope) {
        return;
    }
    let properties_pointer = pointer_join(&secure_pointer, "properties");
    let Some(values) = properties.as_span_array() else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &site.file.path,
            properties_pointer,
            Some(span(properties)),
            format!(
                "{} runtimeConfiguration.secureData.properties must be an array",
                site.label
            ),
        ));
        return;
    };
    for (index, property) in values.iter().enumerate() {
        if is_opaque_arm_expression(site.file, property) {
            continue;
        }
        let pointer = pointer_join(&properties_pointer, &index.to_string());
        let Some(text) = as_string(property) else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &site.file.path,
                pointer,
                Some(span(property)),
                format!(
                    "{} runtimeConfiguration.secureData.properties entries must be strings",
                    site.label
                ),
            ));
            continue;
        };
        if !SECURE_DATA_PROPERTIES
            .iter()
            .any(|allowed| text.eq_ignore_ascii_case(allowed))
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &site.file.path,
                pointer.clone(),
                Some(span(property)),
                format!(
                    "{} runtimeConfiguration.secureData property '{text}' is not supported",
                    site.label
                ),
            ));
        }
        if site.operation_type_known
            && secure_data_property_unsupported(site.operation, site.label, text)
        {
            let operation_type = get(site.operation, "type")
                .and_then(as_string)
                .unwrap_or(site.label);
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &site.file.path,
                pointer,
                Some(span(property)),
                format!(
                    "{operation_type} {} runtimeConfiguration.secureData does not support secure {text}",
                    site.label
                ),
            ));
        }
    }
}

fn secure_data_property_unsupported(
    operation: &json_spanned_value::spanned::Value,
    label: &str,
    property: &str,
) -> bool {
    if label == "trigger" {
        return false;
    }
    if property.eq_ignore_ascii_case("inputs") {
        return common::node_type_is_one_of(operation, SECURE_INPUTS_UNSUPPORTED_OPERATION_TYPES);
    }
    property.eq_ignore_ascii_case("outputs")
        && common::node_type_is_one_of(operation, SECURE_OUTPUTS_UNSUPPORTED_OPERATION_TYPES)
}

/// Cheap probe: does this operation ask for any secureData masking? Used by
/// other rules to decide whether their diagnostics need to redact examples.
pub(super) fn operation_has_secure_data(
    file: &JsonFile,
    operation: &json_spanned_value::spanned::Value,
) -> bool {
    let Some(secure_data) =
        get(operation, "runtimeConfiguration").and_then(|runtime| get(runtime, "secureData"))
    else {
        return false;
    };
    if arm_optional_property_absent(file, secure_data)
        || is_opaque_arm_expression(file, secure_data)
    {
        return false;
    }
    let Some(properties) = get(secure_data, "properties") else {
        return false;
    };
    if arm_optional_property_absent(file, properties) {
        return false;
    }
    properties.as_array().is_some_and(|values| {
        values
            .iter()
            .any(|value| secure_data_property_name(value).is_some())
    })
}

fn secure_data_property_name(value: &json_spanned_value::spanned::Value) -> Option<&str> {
    as_string(value)
        .filter(|name| name.eq_ignore_ascii_case("inputs") || name.eq_ignore_ascii_case("outputs"))
}
