//! Reason about workflow definition parameters and the ARM values that supply
//! them.
//!
//! Two contracts meet here: the definition declares parameters (with types
//! and optional defaults) and the ARM `Microsoft.Logic/workflows` resource
//! supplies values via `properties.parameters`. Whenever an ARM expression
//! cannot be evaluated we conservatively answer "supplied" / "not-required"
//! so the linter never invents a missing-parameter error out of ignorance.
use super::values::{
    is_arm_full_expression, is_arm_full_expression_value, materialized_arm_value_from_spanned,
};
use super::*;

/// True when a `Microsoft.Logic/workflows` properties.parameters entry
/// resolves to a `{ "value": ... }` object with a non-null value.
pub(super) fn arm_workflow_parameter_is_supplied(
    value: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    // Workflow resource parameters use `value`; ARM deployment parameter files
    // may use `reference`, but that shape is not valid here.
    let materialized;
    let value = if is_arm_full_expression_value(value) {
        let Some(value) = materialized_arm_value_from_spanned(value, arm_scope) else {
            return true;
        };
        if is_arm_full_expression_value(&value) {
            return true;
        }
        materialized = value;
        &materialized
    } else {
        value
    };
    as_object(value).is_some_and(|_| {
        get(value, "value").is_some_and(|value| arm_parameter_value_is_present(value, arm_scope))
    })
}

pub(super) fn arm_parameter_value_is_present(
    value: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    if value.is_null() {
        return false;
    }
    if !is_arm_full_expression_value(value) {
        return true;
    }
    let Some(value) = materialized_arm_value_from_spanned(value, arm_scope) else {
        return true;
    };
    if is_arm_full_expression_value(&value) {
        return true;
    }
    !value.is_null()
}

/// Convert the definition's `parameters` block into a list of requirements.
///
/// Handles both authored objects and objects sourced from an ARM full-expression
/// (`"[parameters('foo')]"` that statically resolves to an object). Entries
/// whose ARM value is a resolved null are treated as absent — matching ARM's
/// own "no such parameter" semantics.
pub(super) fn workflow_parameter_requirements(
    definition: &json_spanned_value::spanned::Value,
    definition_pointer: &str,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> Option<Vec<WorkflowParameterRequirement>> {
    let parameters = get(definition, "parameters")?;
    let parameters_pointer = pointer_join(definition_pointer, "parameters");
    if let Some(object) = as_object(parameters) {
        return Some(
            object
                .iter()
                .filter(|(_, parameter)| !arm_definition_entry_absent(parameter, arm_scope))
                .map(|(name, parameter)| WorkflowParameterRequirement {
                    name: name.to_string(),
                    pointer: pointer_join(&parameters_pointer, name),
                    span: span(parameter),
                    requires_value: workflow_parameter_entry_requires_value(
                        name, parameter, arm_scope,
                    ),
                })
                .collect(),
        );
    }

    let text = as_string(parameters)?;
    if !is_arm_full_expression(text) {
        return None;
    }
    let serde_json::Value::Object(object) =
        crate::arm::static_expression_value_with_scope(text, arm_scope)?
    else {
        return None;
    };
    let source_span = span(parameters);
    Some(
        object
            .into_iter()
            .filter(|(_, parameter)| !parameter.is_null())
            .map(|(name, parameter)| {
                let requires_value = name != "$connections"
                    && !materialized_workflow_parameter_default_value_is_present(&parameter);
                WorkflowParameterRequirement {
                    pointer: pointer_join(&parameters_pointer, &name),
                    name,
                    span: source_span,
                    requires_value,
                }
            })
            .collect(),
    )
}

pub(super) fn arm_definition_entry_absent(
    value: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    if value.is_null() {
        return true;
    }
    if !is_arm_full_expression_value(value) {
        return false;
    }
    materialized_arm_value_from_spanned(value, arm_scope)
        .is_some_and(|value| !is_arm_full_expression_value(&value) && value.is_null())
}

/// A definition parameter needs a supplied value unless it is `$connections`
/// (populated by the platform), unreadable through ARM expressions
/// (defensively "not required"), or already carries a `defaultValue`.
pub(super) fn workflow_parameter_entry_requires_value(
    name: &str,
    parameter: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    if name == "$connections" {
        return false;
    }
    let materialized;
    let parameter = if is_arm_full_expression_value(parameter) {
        let Some(value) = materialized_arm_value_from_spanned(parameter, arm_scope) else {
            return false;
        };
        if is_arm_full_expression_value(&value) {
            return false;
        }
        materialized = value;
        &materialized
    } else {
        parameter
    };
    !workflow_parameter_default_value_is_present(parameter, arm_scope)
}

pub(super) fn workflow_parameter_default_value_is_present(
    parameter: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    get(parameter, "defaultValue")
        .is_some_and(|value| arm_parameter_value_is_present(value, arm_scope))
}

pub(super) fn materialized_workflow_parameter_default_value_is_present(
    parameter: &serde_json::Value,
) -> bool {
    parameter
        .as_object()
        .and_then(|object| object.get("defaultValue"))
        .is_some_and(|value| !value.is_null())
}
