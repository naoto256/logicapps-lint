//! Enumerate and classify ARM resource entries.
//!
//! Covers both the array shape and the languageVersion 2.0 symbolic-name
//! shape, the `copy` fan-out and its termination conditions, and the "skip"
//! predicates (`existing`, `condition: false`, `copy.count: 0`) that cause a
//! resource to disappear before deployment. Skipping matches ARM's own
//! semantics so we do not lint away resources that ARM would remove.
use super::nested::{
    materialized_nested_template, nested_template, nested_template_uses_inner_scope,
    nested_template_values, template_defaults_nested_scope_to_inner,
};
use super::values::{materialized_json_value, static_arm_copy_count};
use super::*;

pub(super) fn has_logic_workflow_resource_in(
    value: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    if let Some(resources) = arm_resource_values(value) {
        let current_template_defaults_to_inner = template_defaults_nested_scope_to_inner(value);
        return resources.into_iter().any(|resource| {
            get(resource, "type")
                .and_then(as_string)
                .is_some_and(is_logic_workflow_resource_type)
                || has_logic_workflow_resource_in(resource, arm_scope)
                || nested_template_has_logic_workflow_resource(
                    resource,
                    nested_template(resource),
                    arm_scope,
                    current_template_defaults_to_inner,
                )
                || materialized_nested_template(resource, arm_scope).is_some_and(
                    |(_template_source, template)| {
                        nested_template_has_logic_workflow_resource(
                            resource,
                            Some(&template),
                            arm_scope,
                            current_template_defaults_to_inner,
                        )
                    },
                )
        });
    }
    false
}

pub(super) fn nested_template_has_logic_workflow_resource(
    resource: &json_spanned_value::spanned::Value,
    template: Option<&json_spanned_value::spanned::Value>,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    current_template_defaults_to_inner: bool,
) -> bool {
    let Some(template) = template else {
        return false;
    };
    if nested_template_uses_inner_scope(resource, current_template_defaults_to_inner, arm_scope) {
        let child_values = nested_template_values(resource, template, arm_scope);
        has_logic_workflow_resource_in(template, child_values.scope())
    } else {
        has_logic_workflow_resource_in(template, arm_scope)
    }
}

pub(super) fn is_logic_workflow_resource_type(resource_type: &str) -> bool {
    resource_type.eq_ignore_ascii_case("Microsoft.Logic/workflows")
}

pub(super) fn is_arm_deployment_resource_type(resource_type: &str) -> bool {
    resource_type.eq_ignore_ascii_case("Microsoft.Resources/deployments")
}

pub(super) fn is_existing_arm_resource(
    resource: &json_spanned_value::spanned::Value,
    resource_is_symbolic: bool,
) -> bool {
    resource_is_symbolic
        && get(resource, "existing").and_then(|value| value.as_bool()) == Some(true)
}

/// True when ARM would not materialise this resource: it references an
/// existing resource, its `condition` statically evaluates to false, or its
/// `copy.count` is statically zero.
pub(super) fn is_skipped_arm_resource(
    resource: &json_spanned_value::spanned::Value,
    resource_is_symbolic: bool,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    is_existing_arm_resource(resource, resource_is_symbolic)
        || arm_resource_condition_is_static_false(resource, arm_scope)
        || arm_resource_copy_count_is_static_zero(resource, arm_scope)
}

pub(super) fn arm_resource_condition_is_static_false(
    resource: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    let Some(condition) = get(resource, "condition") else {
        return false;
    };
    if condition.as_bool() == Some(false) {
        return true;
    }
    matches!(
        materialized_json_value(condition, arm_scope),
        Some(serde_json::Value::Bool(false))
    )
}

pub(super) fn arm_resource_copy_count_is_static_zero(
    resource: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    let Some(count) = get(resource, "copy").and_then(|copy| get(copy, "count")) else {
        return false;
    };
    match materialized_json_value(count, arm_scope) {
        Some(serde_json::Value::Number(number)) => {
            number.as_i64() == Some(0) || number.as_u64() == Some(0)
        }
        _ => false,
    }
}

/// Invoke `visit` once per copy iteration, or once with the outer scope when
/// there is no `copy` block. Iteration is bounded by `static_arm_copy_count`
/// so pathological counts cannot explode the analysis.
pub(super) fn for_each_arm_resource_copy_iteration(
    resource: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    mut visit: impl FnMut(crate::arm::ArmStaticScope<'_>),
) {
    let Some(copy) = get(resource, "copy") else {
        visit(arm_scope);
        return;
    };
    let Some(name) = get(copy, "name").and_then(as_string) else {
        visit(arm_scope);
        return;
    };
    let Some(count) = static_arm_copy_count(copy, arm_scope) else {
        visit(arm_scope);
        return;
    };

    for index in 0..count {
        let copy_index = crate::arm::ArmCopyIndex {
            name: name.to_owned(),
            index,
        };
        visit(arm_scope.with_copy_index(&copy_index));
    }
}

pub(super) fn symbolic_resource_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub(super) fn arm_resource_values(
    value: &json_spanned_value::spanned::Value,
) -> Option<Vec<&json_spanned_value::spanned::Value>> {
    let resources = get(value, "resources")?;
    if let Some(array) = resources.as_span_array() {
        return Some(array.iter().collect());
    }
    if template_defaults_nested_scope_to_inner(value) {
        return as_object(resources).map(|object| object.values().collect());
    }
    None
}

/// Return `(pointer, resource, is_symbolic)` triples for each resource entry.
/// `is_symbolic` distinguishes languageVersion 2.0 object-map entries so
/// callers can apply symbolic-only rules (e.g. `existing` handling).
pub(super) fn arm_resource_entries<'a>(
    value: &'a json_spanned_value::spanned::Value,
    pointer: &str,
) -> Vec<(String, &'a json_spanned_value::spanned::Value, bool)> {
    let Some(resources) = get(value, "resources") else {
        return Vec::new();
    };
    let resources_pointer = pointer_join(pointer, "resources");
    if let Some(array) = resources.as_span_array() {
        return array
            .iter()
            .enumerate()
            .map(|(index, resource)| {
                (
                    pointer_join(&resources_pointer, &index.to_string()),
                    resource,
                    false,
                )
            })
            .collect();
    }
    if template_defaults_nested_scope_to_inner(value)
        && let Some(object) = as_object(resources)
    {
        return object
            .iter()
            .map(|(name, resource)| (pointer_join(&resources_pointer, name), resource, true))
            .collect();
    }
    Vec::new()
}
