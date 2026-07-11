//! Reusable field-shape helpers shared across shape rule modules.
//!
//! Every helper follows the same protocol: bail out silently on ARM-optional or
//! opaque ARM expressions, emit `workflow-shape-invalid-type` when the value has
//! the wrong JSON kind, and `workflow-shape-invalid-value` when the value has
//! the right kind but the wrong content. Enum comparisons are case-sensitive to
//! match the published workflowdefinition schema; a separate `_ignore_case`
//! variant exists for the handful of runtime-forgiving fields.

use super::materialized::arm_optional_property_absent;
use super::*;

/// Validate an optional `kind` string against `allowed` and return the resolved
/// literal for callers that dispatch on it.
pub(super) fn validate_optional_kind<'a>(
    action: &'a json_spanned_value::spanned::Value,
    action_pointer: &str,
    label: &str,
    allowed: &[&str],
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<&'a str> {
    let kind_pointer = pointer_join(action_pointer, "kind");
    let kind = get(action, "kind")?;
    if arm_optional_property_absent(file, kind) {
        return None;
    }
    if is_opaque_arm_expression(file, kind) {
        return None;
    }
    let Some(text) = as_string(kind) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            kind_pointer,
            Some(span(kind)),
            format!("{label} must be a string"),
        ));
        return None;
    };
    if !string_in_exact(text, allowed) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            kind_pointer,
            Some(span(kind)),
            format!("{label} '{text}' is not supported"),
        ));
        return None;
    }
    Some(text)
}

/// Optional string enum, case-sensitive comparison.
pub(super) fn validate_optional_string_enum(
    object: &json_spanned_value::spanned::Value,
    object_pointer: &str,
    field: &str,
    label: &str,
    allowed: &[&str],
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(object, field) else {
        return;
    };
    if arm_optional_property_absent(file, value) {
        return;
    }
    if is_opaque_arm_expression(file, value) {
        return;
    }
    let pointer = pointer_join(object_pointer, field);
    let Some(text) = as_string(value) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer,
            Some(span(value)),
            format!("{label} must be a string"),
        ));
        return;
    };
    if !wdl_string_may_match_exact(text, allowed) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer,
            Some(span(value)),
            format!("{label} '{text}' is not supported"),
        ));
    }
}

/// Required counterpart of `validate_optional_string_enum` — emits a missing
/// field diagnostic when absent or when ARM has explicitly nulled it out.
pub(super) fn validate_required_string_enum(
    object: &json_spanned_value::spanned::Value,
    object_pointer: &str,
    field: &str,
    label: &str,
    allowed: &[&str],
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(object, field) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(object)),
            format!("object is missing required field '{field}'"),
        ));
        return;
    };
    if arm_optional_property_absent(file, value) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("object is missing required field '{field}'"),
        ));
        return;
    }
    if is_opaque_arm_expression(file, value) {
        // Full ARM expressions are accepted for scalar fields because their
        // runtime value may satisfy the enum or type constraint.
        return;
    }
    let Some(text) = as_string(value) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} must be a string"),
        ));
        return;
    };
    if !wdl_string_may_match_exact(text, allowed) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} '{text}' is not supported"),
        ));
    }
}

/// Optional string enum where the runtime accepts either casing.
pub(super) fn validate_optional_string_enum_ignore_case(
    object: &json_spanned_value::spanned::Value,
    object_pointer: &str,
    field: &str,
    label: &str,
    allowed: &[&str],
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(object, field) else {
        return;
    };
    if arm_optional_property_absent(file, value) {
        return;
    }
    if is_opaque_arm_expression(file, value) {
        return;
    }
    let Some(text) = as_string(value) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} must be a string"),
        ));
        return;
    };
    if !wdl_string_may_match_exact_ignore_case(text, allowed) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} '{text}' is not supported"),
        ));
    }
}

pub(super) fn validate_optional_string_field(
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
    if arm_optional_property_absent(file, value) {
        return;
    }
    if is_opaque_arm_expression(file, value) {
        return;
    }
    if as_string(value).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} must be a string"),
        ));
    }
}

pub(super) fn validate_optional_integer_field(
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
    if arm_optional_property_absent(file, value) {
        return;
    }
    if is_opaque_arm_expression(file, value) {
        return;
    }
    // Accept WDL expression strings (`@parameters(...)`) as well as literal
    // integers: the runtime evaluates the value when the field fires, so a
    // parameterized count is a legal author-time shape.
    if !is_integer_or_wdl_expression(value) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} must be an integer"),
        ));
    }
}

pub(super) fn validate_optional_bool_field(
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
    if arm_optional_property_absent(file, value) {
        return;
    }
    if is_opaque_arm_expression(file, value) {
        return;
    }
    if value.as_bool().is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} must be a boolean"),
        ));
    }
}

pub(super) fn validate_optional_positive_integer(
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
    if arm_optional_property_absent(file, value) {
        return;
    }
    if is_opaque_arm_expression(file, value) {
        return;
    }
    if !is_positive_integer_or_wdl_expression(value) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} must be a positive integer"),
        ));
    }
}

pub(super) fn validate_optional_integer_range(
    object: &json_spanned_value::spanned::Value,
    object_pointer: &str,
    field: &str,
    label: &str,
    range: (i64, i64),
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(object, field) else {
        return;
    };
    if arm_optional_property_absent(file, value) {
        return;
    }
    if is_opaque_arm_expression(file, value) {
        return;
    }
    let pointer = pointer_join(object_pointer, field);
    let Some(number) = integer_value(value) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer,
            Some(span(value)),
            format!("{label} must be an integer"),
        ));
        return;
    };
    if number < range.0 || number > range.1 {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer,
            Some(span(value)),
            format!("{label} value {number} is out of range"),
        ));
    }
}

pub(super) fn validate_optional_object_field(
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
    if arm_optional_property_absent(file, value) {
        return;
    }
    if is_opaque_arm_expression(file, value) {
        return;
    }
    if as_object(value).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} must be an object"),
        ));
    }
}

/// A resource reference must be an object naming at least one of the accepted
/// address fields (`connectionName`, `id`, `name`, `type`); every field that
/// is present must be a string.
pub(super) fn validate_optional_resource_reference(
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
    if arm_optional_property_absent(file, value) {
        return;
    }
    if is_opaque_arm_expression(file, value) {
        return;
    }
    let pointer = pointer_join(object_pointer, field);
    let Some(object) = as_object(value) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer,
            Some(span(value)),
            format!("{label} must be an object"),
        ));
        return;
    };
    if !["connectionName", "id", "name", "type"]
        .iter()
        .any(|reference_field| object.contains_key(*reference_field))
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(&pointer, "id"),
            Some(span(value)),
            format!("{label} must define at least one of connectionName, id, name, or type"),
        ));
    }
    for reference_field in ["connectionName", "id", "name", "type"] {
        validate_optional_string_field(
            value,
            &pointer,
            reference_field,
            &format!("{label}.{reference_field}"),
            file,
            diagnostics,
        );
    }
}

/// Optional field that may be an object (whose values must be scalar) or a
/// bare string. Used for HTTP-style `headers` and other "map-or-string" shapes.
pub(in crate::check::shape) fn validate_optional_object_or_string_field(
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
    if as_object(value).is_some() {
        validate_scalar_object_values(
            value,
            &pointer_join(object_pointer, field),
            label,
            file,
            diagnostics,
        );
    } else if as_string(value).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} must be an object or string"),
        ));
    }
}

// visibility raised for shape::http — the object-or-string helper above lives
// here, while `validate_optional_object_or_wdl_expression_field` in shape::http
// also needs to enforce the same scalar-values rule.
pub(in crate::check::shape) fn validate_scalar_object_values(
    value: &json_spanned_value::spanned::Value,
    object_pointer: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(object) = as_object(value) else {
        return;
    };
    for (name, value) in object {
        if is_opaque_arm_expression(file, value) {
            continue;
        }
        if as_object(value).is_some() || value.as_span_array().is_some() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                pointer_join(object_pointer, name),
                Some(span(value)),
                format!("{label} values must be scalar"),
            ));
        }
    }
}

pub(super) fn string_in_exact(value: &str, allowed: &[&str]) -> bool {
    // Public workflowdefinition schema enums are case-sensitive even though many
    // action-type dispatches above are forgiving for authored files.
    allowed.contains(&value)
}
