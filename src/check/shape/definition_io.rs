//! `definition.parameters` and `definition.outputs` shape checks.
//!
//! Both surfaces share the same declaration grammar: an object keyed by name,
//! each entry naming a Logic Apps parameter type plus optional defaults or
//! values. This module enforces the common type enum, the type/value shape
//! match, and the "defaultValue is required for authored workflows" rule.
//! Under ARM, defaults are frequently supplied by the deployment, so the
//! required-default rule relaxes there.

use super::materialized::{arm_optional_property_absent, static_string_from_spanned};
use super::*;
use std::collections::BTreeSet;

// Case-sensitive enum shared by parameters and outputs.
const PARAMETER_TYPES: &[&str] = &[
    "Array",
    "Bool",
    "Float",
    "Int",
    "Object",
    "SecureObject",
    "SecureString",
    "String",
];

/// Validate each `definition.parameters` entry.
///
/// `known_parameters` is the union of parameters supplied by the enclosing
/// project (`parameters.json`, ARM defaults). `default_values_required` is set
/// when the file is a standalone workflow: authored workflows must ship a
/// `defaultValue` unless another layer contributes one.
pub(super) fn validate_definition_parameters(
    parameters: &json_spanned_value::spanned::Value,
    parameters_pointer: &str,
    file: &JsonFile,
    known_parameters: &BTreeSet<String>,
    default_values_required: bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(object) = as_object(parameters) else {
        return;
    };
    for (name, parameter) in object.iter() {
        let parameter_pointer = pointer_join(parameters_pointer, name);
        if arm_optional_property_absent(file, parameter) {
            continue;
        }
        if is_opaque_arm_expression(file, parameter) {
            // ARM can synthesize one parameter declaration entry.
            continue;
        }
        if as_object(parameter).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                parameter_pointer,
                Some(span(parameter)),
                "definition parameter entries must be objects",
            ));
            continue;
        }
        let Some(parameter_type) = get(parameter, "type") else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-missing-field",
                &file.path,
                pointer_join(&parameter_pointer, "type"),
                Some(span(parameter)),
                "definition parameter is missing required field 'type'",
            ));
            continue;
        };
        let parameter_type_text = definition_entry_type_text(file, parameter_type);
        if let Some(parameter_type_text) = parameter_type_text.as_deref() {
            if !string_in_exact(parameter_type_text, PARAMETER_TYPES) {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-value",
                    &file.path,
                    pointer_join(&parameter_pointer, "type"),
                    Some(span(parameter_type)),
                    format!("definition parameter type '{parameter_type_text}' is not supported"),
                ));
            }
        } else if !is_opaque_arm_expression(file, parameter_type) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                pointer_join(&parameter_pointer, "type"),
                Some(span(parameter_type)),
                "definition parameter type must be a string",
            ));
            continue;
        }
        // Opaque type expression: nothing further to check on this entry.
        if parameter_type_text.is_none() && is_opaque_arm_expression(file, parameter_type) {
            continue;
        }
        let default_value_required = definition_parameter_default_value_required(
            file,
            name,
            known_parameters,
            default_values_required,
        );
        if let Some(default_value) = get(parameter, "defaultValue") {
            if arm_optional_property_absent(file, default_value) {
                if default_value_required {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-missing-field",
                        &file.path,
                        pointer_join(&parameter_pointer, "defaultValue"),
                        Some(span(default_value)),
                        "definition parameter is missing required field 'defaultValue'",
                    ));
                }
            } else if let Some(parameter_type_text) = parameter_type_text.as_deref()
                && string_in_exact(parameter_type_text, PARAMETER_TYPES)
            {
                validate_definition_parameter_default_value(
                    default_value,
                    parameter_type_text,
                    &parameter_pointer,
                    file,
                    diagnostics,
                );
            }
        } else if default_value_required {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-missing-field",
                &file.path,
                pointer_join(&parameter_pointer, "defaultValue"),
                Some(span(parameter)),
                "definition parameter is missing required field 'defaultValue'",
            ));
        }
        if let Some(allowed_values) = get(parameter, "allowedValues")
            && !arm_optional_property_absent(file, allowed_values)
            && !is_opaque_arm_expression(file, allowed_values)
            && allowed_values.as_array().is_none()
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                pointer_join(&parameter_pointer, "allowedValues"),
                Some(span(allowed_values)),
                "definition parameter allowedValues must be an array",
            ));
        }
        validate_optional_string_field(
            parameter,
            &parameter_pointer,
            "description",
            "definition parameter description",
            file,
            diagnostics,
        );
        common::validate_optional_description_length(
            parameter,
            &parameter_pointer,
            "definition parameter",
            file,
            diagnostics,
        );
    }
}

fn definition_parameter_default_value_required(
    file: &JsonFile,
    name: &str,
    known_parameters: &BTreeSet<String>,
    default_values_required: bool,
) -> bool {
    // `$connections` is populated by the runtime, ARM templates supply defaults
    // externally, and any parameter the enclosing project already declares does
    // not need to repeat its default here.
    default_values_required
        && name != "$connections"
        && !file_allows_arm_expressions(file)
        && !known_parameters.contains(name)
}

/// Resolve a parameter/output `type` to a literal string when possible.
/// Materialized ARM expressions win over a raw string; a truly opaque expression
/// yields `None` so callers can distinguish "unknown" from "invalid type".
fn definition_entry_type_text(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
) -> Option<String> {
    if let Some(text) = static_string_from_spanned(file, value) {
        return Some(text);
    }
    if is_opaque_arm_expression(file, value) {
        return None;
    }
    as_string(value).map(str::to_owned)
}

fn validate_definition_parameter_default_value(
    value: &json_spanned_value::spanned::Value,
    parameter_type: &str,
    parameter_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if definition_io_value_is_dynamic_json(file, value) {
        return;
    }
    if definition_io_value_matches_type(value, parameter_type) {
        return;
    }
    diagnostics.push(Diagnostic::error(
        "workflow-shape-invalid-type",
        &file.path,
        pointer_join(parameter_pointer, "defaultValue"),
        Some(span(value)),
        format!("definition parameter defaultValue must match type '{parameter_type}'"),
    ));
}

/// A default/value is considered dynamic when its runtime shape cannot be
/// determined statically — an opaque ARM expression or a WDL string that
/// resolves at evaluation time.
fn definition_io_value_is_dynamic_json(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
) -> bool {
    is_opaque_arm_expression(file, value)
        || as_string(value).is_some_and(wdl_string_is_full_expression)
}

fn definition_io_value_matches_type(
    value: &json_spanned_value::spanned::Value,
    parameter_type: &str,
) -> bool {
    match parameter_type {
        "Array" => value.as_array().is_some(),
        "Bool" => value.as_bool().is_some(),
        "Float" => value.as_number().is_some(),
        "Int" => value
            .as_number()
            .is_some_and(|number| number.as_i64().is_some() || number.as_u64().is_some()),
        "Object" | "SecureObject" => value.as_object().is_some(),
        "SecureString" | "String" => as_string(value).is_some(),
        _ => true,
    }
}

/// Validate each `definition.outputs` entry. Outputs share the parameter type
/// grammar but require `value` instead of `defaultValue`.
pub(super) fn validate_definition_outputs(
    outputs: &json_spanned_value::spanned::Value,
    outputs_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(object) = as_object(outputs) else {
        return;
    };
    for (name, output) in object.iter() {
        let output_pointer = pointer_join(outputs_pointer, name);
        if arm_optional_property_absent(file, output) {
            continue;
        }
        if is_opaque_arm_expression(file, output) {
            // ARM can synthesize one output declaration entry.
            continue;
        }
        if as_object(output).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                output_pointer,
                Some(span(output)),
                "definition output entries must be objects",
            ));
            continue;
        }
        let Some(output_type) = get(output, "type") else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-missing-field",
                &file.path,
                pointer_join(&output_pointer, "type"),
                Some(span(output)),
                "definition output is missing required field 'type'",
            ));
            continue;
        };
        let output_type_text = definition_entry_type_text(file, output_type);
        if let Some(output_type_text) = output_type_text.as_deref() {
            if !string_in_exact(output_type_text, PARAMETER_TYPES) {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-value",
                    &file.path,
                    pointer_join(&output_pointer, "type"),
                    Some(span(output_type)),
                    format!("definition output type '{output_type_text}' is not supported"),
                ));
            }
        } else if !is_opaque_arm_expression(file, output_type) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                pointer_join(&output_pointer, "type"),
                Some(span(output_type)),
                "definition output type must be a string",
            ));
            continue;
        }
        if let Some(value) = get(output, "value") {
            if let Some(output_type_text) = output_type_text.as_deref()
                && string_in_exact(output_type_text, PARAMETER_TYPES)
                && !definition_io_value_is_dynamic_json(file, value)
                && !definition_io_value_matches_type(value, output_type_text)
            {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-type",
                    &file.path,
                    pointer_join(&output_pointer, "value"),
                    Some(span(value)),
                    format!("definition output value must match type '{output_type_text}'"),
                ));
            }
        } else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-missing-field",
                &file.path,
                pointer_join(&output_pointer, "value"),
                Some(span(output)),
                "definition output is missing required field 'value'",
            ));
        }
        validate_optional_string_field(
            output,
            &output_pointer,
            "description",
            "definition output description",
            file,
            diagnostics,
        );
        common::validate_optional_description_length(
            output,
            &output_pointer,
            "definition output",
            file,
            diagnostics,
        );
    }
}
