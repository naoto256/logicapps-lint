//! Extract variable-related metadata from a single action body.
//!
//! Four things live here: variables declared by `InitializeVariable` (name and
//! type), the mutation target of `SetVariable`/`AppendTo*`/`Increment` etc.,
//! and the string values assigned by `SetVariable` (used by type-consistency
//! rules). All queries dispatch on `type` via [`static_string_from_spanned`]
//! so an ARM-materialized action type still classifies correctly.

use super::arm_support::static_string_from_spanned;
use super::*;
use crate::json::{as_object, as_string, get, pointer_join, span};
use json_spanned_value::spanned;

/// Collect variables initialized by an `InitializeVariable` action.
///
/// Supports both the single-variable shape (`inputs.name` / `inputs.type`)
/// and the array shape (`inputs.variables[]`). Returns `Vec::new()` when the
/// action is not an initializer or when no valid entries are found.
pub(super) fn initialized_variables_from_spanned(
    value: &spanned::Value,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> Vec<InitializedVariable> {
    if !get(value, "type")
        .and_then(|value| static_string_from_spanned(value, arm_scope))
        .is_some_and(|action_type| action_type.eq_ignore_ascii_case("InitializeVariable"))
    {
        return Vec::new();
    }
    let Some(inputs) = get(value, "inputs") else {
        return Vec::new();
    };
    if let Some(variable_values) =
        get(inputs, "variables").and_then(|variables| variables.as_span_array())
    {
        variable_values
            .iter()
            .filter_map(|value| initialized_variable_from_spanned(value, arm_scope))
            .collect()
    } else {
        initialized_variable_from_spanned(inputs, arm_scope)
            .into_iter()
            .collect()
    }
}

/// Locate the target variable name of a mutation action, or `None` when the
/// action is not a mutation type or the name literal cannot be read.
pub(super) fn variable_target_from_spanned(
    value: &spanned::Value,
    action_pointer: &str,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> Option<VariableTarget> {
    if !get(value, "type")
        .and_then(|value| static_string_from_spanned(value, arm_scope))
        .as_deref()
        .is_some_and(is_variable_mutation_type)
    {
        return None;
    }
    let name_value = get(value, "inputs").and_then(|inputs| get(inputs, "name"))?;
    let name = as_string(name_value)?;
    Some(VariableTarget {
        name: name.to_owned(),
        pointer: pointer_join(&pointer_join(action_pointer, "inputs"), "name"),
        span: span(name_value),
    })
}

/// Collect every string leaf under a `SetVariable` action's `inputs.value`.
///
/// Only `SetVariable` — the increment/append actions have their own value
/// shapes and are handled by dedicated rules. `None` when the action is not a
/// `SetVariable` or when no string leaves exist.
pub(super) fn variable_value_from_spanned(
    value: &spanned::Value,
    action_pointer: &str,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> Option<VariableValue> {
    if !get(value, "type")
        .and_then(|value| static_string_from_spanned(value, arm_scope))
        .is_some_and(|action_type| action_type.eq_ignore_ascii_case("SetVariable"))
    {
        return None;
    }
    let value_node = get(value, "inputs").and_then(|inputs| get(inputs, "value"))?;
    let values = string_values_from_spanned(value_node);
    if values.is_empty() {
        return None;
    }
    Some(VariableValue {
        values,
        pointer: pointer_join(&pointer_join(action_pointer, "inputs"), "value"),
        span: span(value_node),
    })
}

fn initialized_variable_from_spanned(
    value: &spanned::Value,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> Option<InitializedVariable> {
    let variable_type =
        get(value, "type").and_then(|value| static_string_from_spanned(value, arm_scope))?;
    if !is_variable_type(&variable_type) {
        return None;
    }
    let name = get(value, "name").and_then(as_string)?;
    Some(InitializedVariable {
        name: name.to_owned(),
        variable_type,
    })
}

/// Serde-json variant of [`initialized_variables_from_spanned`] used past the
/// ARM boundary. No scope needed here — expressions are already materialized.
pub(super) fn initialized_variables_from_json(
    value: &serde_json::Value,
) -> Vec<InitializedVariable> {
    if !value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|action_type| action_type.eq_ignore_ascii_case("InitializeVariable"))
    {
        return Vec::new();
    }
    let Some(inputs) = value.get("inputs") else {
        return Vec::new();
    };
    if let Some(variable_values) = inputs
        .get("variables")
        .and_then(serde_json::Value::as_array)
    {
        variable_values
            .iter()
            .filter_map(initialized_variable_from_json)
            .collect()
    } else {
        initialized_variable_from_json(inputs).into_iter().collect()
    }
}

/// Serde-json variant of [`variable_target_from_spanned`].
pub(super) fn variable_target_from_json(
    value: &serde_json::Value,
    action_pointer: &str,
    source_span: crate::diagnostic::ByteSpan,
) -> Option<VariableTarget> {
    if !value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(is_variable_mutation_type)
    {
        return None;
    }
    let name = value
        .get("inputs")
        .and_then(|inputs| inputs.get("name"))
        .and_then(serde_json::Value::as_str)?;
    Some(VariableTarget {
        name: name.to_owned(),
        pointer: pointer_join(&pointer_join(action_pointer, "inputs"), "name"),
        span: source_span,
    })
}

/// Serde-json variant of [`variable_value_from_spanned`].
pub(super) fn variable_value_from_json(
    value: &serde_json::Value,
    action_pointer: &str,
    source_span: crate::diagnostic::ByteSpan,
) -> Option<VariableValue> {
    if !value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|action_type| action_type.eq_ignore_ascii_case("SetVariable"))
    {
        return None;
    }
    let value_node = value.get("inputs").and_then(|inputs| inputs.get("value"))?;
    let values = string_values_from_json(value_node);
    if values.is_empty() {
        return None;
    }
    Some(VariableValue {
        values,
        pointer: pointer_join(&pointer_join(action_pointer, "inputs"), "value"),
        span: source_span,
    })
}

fn string_values_from_spanned(value: &spanned::Value) -> Vec<String> {
    let mut strings = Vec::new();
    collect_string_values_from_spanned(value, &mut strings);
    strings
}

fn collect_string_values_from_spanned(value: &spanned::Value, strings: &mut Vec<String>) {
    if let Some(text) = as_string(value) {
        strings.push(text.to_owned());
        return;
    }
    if let Some(object) = as_object(value) {
        for (_, child) in object.iter() {
            collect_string_values_from_spanned(child, strings);
        }
    } else if let Some(array) = value.as_span_array() {
        for child in array.iter() {
            collect_string_values_from_spanned(child, strings);
        }
    }
}

fn string_values_from_json(value: &serde_json::Value) -> Vec<String> {
    let mut strings = Vec::new();
    collect_string_values_from_json(value, &mut strings);
    strings
}

fn collect_string_values_from_json(value: &serde_json::Value, strings: &mut Vec<String>) {
    if let Some(text) = value.as_str() {
        strings.push(text.to_owned());
        return;
    }
    if let Some(object) = value.as_object() {
        for child in object.values() {
            collect_string_values_from_json(child, strings);
        }
    } else if let Some(array) = value.as_array() {
        for child in array {
            collect_string_values_from_json(child, strings);
        }
    }
}

fn initialized_variable_from_json(value: &serde_json::Value) -> Option<InitializedVariable> {
    let variable_type = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)?;
    if !is_variable_type(&variable_type) {
        return None;
    }
    let name = value.get("name").and_then(serde_json::Value::as_str)?;
    Some(InitializedVariable {
        name: name.to_owned(),
        variable_type,
    })
}

/// Whitelisted `InitializeVariable` type names. Both PascalCase (schema-blessed)
/// and lowercase (accepted leniently by the runtime) are honored so we do not
/// falsely reject valid definitions.
fn is_variable_type(variable_type: &str) -> bool {
    matches!(
        variable_type,
        "Array"
            | "Boolean"
            | "Float"
            | "Integer"
            | "Object"
            | "String"
            | "array"
            | "boolean"
            | "float"
            | "integer"
            | "object"
            | "string"
    )
}

/// The five action types that write to a variable — used to gate
/// [`variable_target_from_spanned`]/`_json`. Case-insensitive to match runtime.
fn is_variable_mutation_type(action_type: &str) -> bool {
    action_type.eq_ignore_ascii_case("SetVariable")
        || action_type.eq_ignore_ascii_case("AppendToArrayVariable")
        || action_type.eq_ignore_ascii_case("AppendToStringVariable")
        || action_type.eq_ignore_ascii_case("IncrementVariable")
        || action_type.eq_ignore_ascii_case("DecrementVariable")
}
