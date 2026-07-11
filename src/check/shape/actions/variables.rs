//! Shape validators for the variable action family: `InitializeVariable`,
//! `SetVariable`, `AppendToArrayVariable`, `AppendToStringVariable`,
//! `IncrementVariable`, `DecrementVariable`. Self-reference detection for
//! `SetVariable` lives in the reference layer, not here.

use super::*;

const VARIABLE_TYPES: &[&str] = &["Array", "Boolean", "Float", "Integer", "Object", "String"];

/// Validate `InitializeVariable`. Two authoring shapes are accepted: the
/// legacy single-variable form (`inputs.{name,type,value}`) and the newer
/// `inputs.variables: [...]` array. Must be declared at the workflow action
/// root so downstream availability checks can reason statically.
pub(in crate::check::shape) fn validate_initialize_variable_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    container_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !is_top_level_action_container(container_pointer) {
        // Logic Apps initializes variables only at the workflow action root;
        // nested initialization creates misleading availability for later checks.
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            action_pointer.to_owned(),
            Some(span(action)),
            "InitializeVariable actions must be declared at the workflow action root",
        ));
    }
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    let inputs_pointer = pointer_join(action_pointer, "inputs");
    let Some(variables) = get(inputs, "variables") else {
        // Authoring tools emit both the old single-variable shape and the
        // newer `variables: [...]` shape; validate both without normalizing.
        validate_variable_initializer(inputs, &inputs_pointer, file, diagnostics);
        return;
    };
    let Some(variable_entries) = variables.as_span_array() else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(&inputs_pointer, "variables"),
            Some(span(variables)),
            "InitializeVariable inputs.variables must be an array",
        ));
        return;
    };
    if variable_entries.is_empty() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-shape",
            &file.path,
            pointer_join(&inputs_pointer, "variables"),
            Some(span(variables)),
            "InitializeVariable inputs.variables must contain at least one variable",
        ));
        return;
    }
    for (index, variable) in variable_entries.iter().enumerate() {
        let variable_pointer = pointer_join(
            &pointer_join(&inputs_pointer, "variables"),
            &index.to_string(),
        );
        if as_object(variable).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                variable_pointer,
                Some(span(variable)),
                "InitializeVariable variable entries must be objects",
            ));
            continue;
        }
        validate_variable_initializer(variable, &variable_pointer, file, diagnostics);
    }
}

/// Validate one variable initializer entry (`name`, `type`) — shared
/// between the flat and array authoring shapes.
pub(in crate::check::shape) fn validate_variable_initializer(
    object: &json_spanned_value::spanned::Value,
    object_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    require_typed_field(
        object,
        object_pointer,
        "name",
        "InitializeVariable variable name must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    let Some(variable_type) = get(object, "type") else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(object_pointer, "type"),
            Some(span(object)),
            "InitializeVariable variable is missing required field 'type'",
        ));
        return;
    };
    let Some(variable_type_text) = as_string(variable_type) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(object_pointer, "type"),
            Some(span(variable_type)),
            "InitializeVariable variable type must be a string",
        ));
        return;
    };
    if !VARIABLE_TYPES
        .iter()
        .any(|allowed| variable_type_text.eq_ignore_ascii_case(allowed))
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(object_pointer, "type"),
            Some(span(variable_type)),
            format!("InitializeVariable variable type '{variable_type_text}' is not supported"),
        ));
    }
}

/// Validate a variable update action. Handles Set/Append/Increment/Decrement
/// in a single pass: `name` is always required; `value` is required for the
/// set/append family; Increment/Decrement additionally require a numeric or
/// dynamic value and reject non-numeric target variables when the type is
/// statically known.
pub(in crate::check::shape) fn validate_variable_update_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    action_type: &str,
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
        "name",
        "variable action inputs.name must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    if action_type.eq_ignore_ascii_case("SetVariable")
        || action_type.eq_ignore_ascii_case("AppendToArrayVariable")
        || action_type.eq_ignore_ascii_case("AppendToStringVariable")
    {
        // Increment/Decrement default to 1 when value is omitted, but set/append
        // actions have no useful default target value.
        require_typed_field(
            inputs,
            &inputs_pointer,
            "value",
            "variable action inputs.value must be present",
            file,
            diagnostics,
            |_| true,
        );
    }
    if (action_type.eq_ignore_ascii_case("IncrementVariable")
        || action_type.eq_ignore_ascii_case("DecrementVariable"))
        && let Some(value) = get(inputs, "value")
        && !is_opaque_arm_expression(file, value)
        && !variable_delta_value_is_numeric_or_dynamic(value)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(&inputs_pointer, "value"),
            Some(span(value)),
            format!("{action_type} inputs.value must be a number or expression string"),
        ));
    }
    if action_type.eq_ignore_ascii_case("IncrementVariable")
        || action_type.eq_ignore_ascii_case("DecrementVariable")
    {
        validate_numeric_variable_target(
            inputs,
            &inputs_pointer,
            action_type,
            file,
            workflow,
            diagnostics,
        );
    }
    validate_optional_string_enum(
        inputs,
        &inputs_pointer,
        "type",
        "variable action inputs.type",
        VARIABLE_TYPES,
        file,
        diagnostics,
    );
}

// Increment/Decrement target: locate every InitializeVariable at the
// workflow action root that declares this name and refuse if none of the
// declared types are numeric. Empty set means unknown (probably ARM- or
// dynamically-defined) and is left alone to avoid false positives.
fn validate_numeric_variable_target(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    action_type: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(name_value) = get(inputs, "name") else {
        return;
    };
    if is_opaque_arm_expression(file, name_value) {
        return;
    }
    let Some(name) = as_string(name_value) else {
        return;
    };
    let top_level_actions = pointer_join(&workflow.definition_pointer, "actions");
    let known_types = workflow
        .action_list
        .iter()
        .filter(|action| action.container_pointer == top_level_actions)
        .flat_map(|action| action.initialized_variables.iter())
        .filter(|variable| variable.name == name)
        .map(|variable| variable.variable_type.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if known_types.is_empty()
        || known_types
            .iter()
            .any(|variable_type| variable_type_is_numeric(variable_type))
    {
        return;
    }
    let types = known_types.into_iter().collect::<Vec<_>>().join(", ");
    diagnostics.push(Diagnostic::error(
        "workflow-shape-invalid-context",
        &file.path,
        pointer_join(inputs_pointer, "name"),
        Some(span(name_value)),
        format!("{action_type} targets non-numeric variable '{name}' of type '{types}'"),
    ));
}

fn variable_type_is_numeric(variable_type: &str) -> bool {
    variable_type.eq_ignore_ascii_case("Integer") || variable_type.eq_ignore_ascii_case("Float")
}

fn variable_delta_value_is_numeric_or_dynamic(value: &json_spanned_value::spanned::Value) -> bool {
    value.as_number().is_some() || as_string(value).is_some_and(wdl_string_may_be_finite_number)
}

/// True if the container is the workflow's root `actions` object (not a
/// nested `.../actions/<something>/actions`). Used to enforce that variable
/// initialization happens at the top level.
pub(in crate::check::shape) fn is_top_level_action_container(container_pointer: &str) -> bool {
    let Some(prefix) = container_pointer.strip_suffix("/actions") else {
        return false;
    };
    !prefix.contains("/actions/")
}
