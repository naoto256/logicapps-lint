//! Helpers that enforce the presence and shape of required fields.
//!
//! Missing fields produce `workflow-shape-missing-field`; present-but-wrong-type
//! fields produce `workflow-shape-invalid-type`. Opaque ARM expressions are
//! accepted at the boundary: when possible we still peek at their statically
//! resolvable form so that a template producing a non-object still gets flagged.

use super::materialized::static_json_value_from_spanned;
use super::*;

/// Fetch the required `inputs` object for an action.
///
/// When `inputs` is an ARM expression, try to resolve it statically: if the
/// resolved value is neither an object nor null, emit the wrong-type diagnostic
/// against the ARM source span. In all opaque-ARM branches the returned value
/// is `None` — subsequent per-field checks are skipped because the object body
/// is not available.
pub(super) fn required_inputs_object<'a>(
    action: &'a json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<&'a json_spanned_value::spanned::Value> {
    let Some(inputs) = get(action, "inputs") else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(action_pointer, "inputs"),
            Some(span(action)),
            "action is missing required object field 'inputs'",
        ));
        return None;
    };
    if is_opaque_arm_expression(file, inputs) {
        if let Some((value, source_span)) = static_json_value_from_spanned(file, inputs)
            && !value.is_object()
            && !value.is_null()
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                pointer_join(action_pointer, "inputs"),
                Some(source_span),
                "action field 'inputs' must be an object",
            ));
        }
        // Inputs can be an ARM expression that materializes the whole object.
        return None;
    }
    if as_object(inputs).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(action_pointer, "inputs"),
            Some(span(inputs)),
            "action field 'inputs' must be an object",
        ));
        return None;
    }
    Some(inputs)
}

/// Trigger counterpart. Triggers don't get the resolve-and-typecheck detour
/// because the ARM-produced trigger shapes we see in practice always keep the
/// outermost object literal.
pub(super) fn required_trigger_inputs_object<'a>(
    trigger: &'a json_spanned_value::spanned::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<&'a json_spanned_value::spanned::Value> {
    let Some(inputs) = get(trigger, "inputs") else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(trigger_pointer, "inputs"),
            Some(span(trigger)),
            "trigger is missing required object field 'inputs'",
        ));
        return None;
    };
    if is_opaque_arm_expression(file, inputs) {
        // Inputs can be an ARM expression that materializes the whole object.
        return None;
    }
    if as_object(inputs).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(trigger_pointer, "inputs"),
            Some(span(inputs)),
            "trigger field 'inputs' must be an object",
        ));
        return None;
    }
    Some(inputs)
}

/// Presence-only check. Type validation belongs to the caller.
pub(super) fn require_field(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    field: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if get(action, field).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(action_pointer, field),
            Some(span(action)),
            format!("action is missing required field '{field}'"),
        ));
    }
}

/// Presence + object-type check. Opaque ARM values pass the type check.
pub(super) fn require_object_field(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    field: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(action, field) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(action_pointer, field),
            Some(span(action)),
            format!("action is missing required object field '{field}'"),
        ));
        return;
    };
    if !is_opaque_arm_expression(file, value) && as_object(value).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(action_pointer, field),
            Some(span(value)),
            format!("action field '{field}' must be an object"),
        ));
    }
}

/// Presence + custom predicate. Callers supply the predicate so unusual shapes
/// (e.g. "string or integer") stay expressible without another helper.
pub(super) fn require_typed_field(
    object: &json_spanned_value::spanned::Value,
    object_pointer: &str,
    field: &str,
    type_message: &'static str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
    valid: impl Fn(&json_spanned_value::spanned::Value) -> bool,
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
    if !is_opaque_arm_expression(file, value) && !valid(value) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            type_message,
        ));
    }
}
