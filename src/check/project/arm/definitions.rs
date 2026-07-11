//! Walk ARM (and ARM-like) templates and produce workflow definition candidates.
//!
//! Two shapes coexist:
//!
//! - definitions authored directly under a resource — the "source" candidate
//!   points at the authored span so diagnostics land on the human's bytes;
//! - definitions produced by expanding ARM expressions or nested-template
//!   materialisation — the candidate carries a materialised copy alongside a
//!   pointer back into the original template so spans still resolve.
//!
//! Nested deployments inherit or replace the ARM scope depending on the
//! `expressionEvaluationOptions.scope` field and the outer template's
//! `languageVersion` — those two knobs drive the branches here.
use super::detect::{is_embedded_workflow_definition, is_workflow_definition};
use super::nested::{
    materialized_nested_template, nested_template, nested_template_outer_scope_blocked,
    nested_template_pointer, nested_template_uses_inner_scope, nested_template_values,
    template_defaults_nested_scope_to_inner,
};
use super::resources::{
    arm_resource_entries, for_each_arm_resource_copy_iteration, is_logic_workflow_resource_type,
    is_skipped_arm_resource,
};
use super::values::materialized_arm_value_from_spanned;
use super::*;

/// Recursive scan for embedded workflow bodies in ARM-adjacent payloads that
/// do not follow the ARM `resources[*].properties.definition` layout — e.g.
/// public-schema fixtures. Only positions that match a real schema or the
/// ARM path count, to avoid false positives on unrelated JSON.
pub(super) fn collect_embedded_workflow_definitions<'a>(
    value: &'a json_spanned_value::spanned::Value,
    pointer: &str,
    out: &mut Vec<WorkflowDefinitionCandidate<'a>>,
) {
    // Only treat nested objects as workflows when they match the public schema
    // or the ARM `/properties/definition` location. Many payloads can contain
    // `actions` or `triggers` keys that are not Logic Apps definitions.
    if is_workflow_definition(value) || is_embedded_workflow_definition(value, pointer) {
        out.push(WorkflowDefinitionCandidate {
            value,
            materialized: None,
            value_is_definition_source: true,
            arm_values: None,
            pointer: pointer.to_owned(),
            kind: None,
            kind_invalid_type: None,
        });
        return;
    }

    if let Some(object) = as_object(value) {
        for (key, child) in object.iter() {
            collect_embedded_workflow_definitions(child, &pointer_join(pointer, key), out);
        }
        return;
    }

    if let Some(array) = value.as_span_array() {
        for (index, child) in array.iter().enumerate() {
            collect_embedded_workflow_definitions(
                child,
                &pointer_join(pointer, &index.to_string()),
                out,
            );
        }
    }
}

/// Entry point for extracting definitions from an ARM template. Determines
/// the enclosing template's default scope for nested deployments before
/// walking resources.
pub(super) fn collect_logic_workflow_resource_definitions<'a>(
    value: &'a json_spanned_value::spanned::Value,
    pointer: &str,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    out: &mut Vec<WorkflowDefinitionCandidate<'a>>,
) {
    let current_template_defaults_to_inner = template_defaults_nested_scope_to_inner(value);
    collect_logic_workflow_resource_definitions_in(
        value,
        pointer,
        arm_scope,
        current_template_defaults_to_inner,
        out,
    );
}

pub(super) fn collect_logic_workflow_resource_definitions_in<'a>(
    value: &'a json_spanned_value::spanned::Value,
    pointer: &str,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    current_template_defaults_to_inner: bool,
    out: &mut Vec<WorkflowDefinitionCandidate<'a>>,
) {
    for (resource_pointer, resource, resource_is_symbolic) in arm_resource_entries(value, pointer) {
        collect_logic_workflow_resource_definition_entry(
            resource,
            &resource_pointer,
            resource_is_symbolic,
            arm_scope,
            current_template_defaults_to_inner,
            out,
        );
    }
}

pub(super) fn collect_logic_workflow_resource_definition_entry<'a>(
    resource: &'a json_spanned_value::spanned::Value,
    resource_pointer: &str,
    resource_is_symbolic: bool,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    current_template_defaults_to_inner: bool,
    out: &mut Vec<WorkflowDefinitionCandidate<'a>>,
) {
    if is_skipped_arm_resource(resource, resource_is_symbolic, arm_scope) {
        return;
    }
    if get(resource, "type")
        .and_then(as_string)
        .is_some_and(is_logic_workflow_resource_type)
    {
        if let Some(definition) = get(resource, "properties").and_then(|v| get(v, "definition")) {
            let materialized = materialized_arm_value_from_spanned(definition, arm_scope);
            out.push(WorkflowDefinitionCandidate {
                value: definition,
                materialized,
                value_is_definition_source: true,
                arm_values: StaticArmValues::from_scope(arm_scope),
                pointer: pointer_join(&pointer_join(resource_pointer, "properties"), "definition"),
                kind: get(resource, "kind").and_then(as_string).map(str::to_owned),
                kind_invalid_type: get(resource, "kind")
                    .filter(|kind| as_string(kind).is_none())
                    .map(|kind| (pointer_join(resource_pointer, "kind"), span(kind))),
            });
        }
        return;
    }

    // `copy` fans a resource out into N iterations. Each iteration gets its
    // own scope that binds the copy index so `copyIndex(...)` resolves; when
    // no `copy` is present the closure runs exactly once with the outer scope.
    for_each_arm_resource_copy_iteration(resource, arm_scope, |iteration_scope| {
        if let Some(template) = nested_template(resource) {
            collect_nested_logic_workflow_resource_definitions(
                resource,
                resource_pointer,
                template,
                iteration_scope,
                current_template_defaults_to_inner,
                out,
            );
        } else if let Some((template_source, template)) =
            materialized_nested_template(resource, iteration_scope)
        {
            collect_materialized_nested_logic_workflow_resource_definitions(
                resource,
                resource_pointer,
                template_source,
                &template,
                iteration_scope,
                current_template_defaults_to_inner,
                out,
            );
        }

        collect_logic_workflow_resource_definitions_in(
            resource,
            resource_pointer,
            iteration_scope,
            current_template_defaults_to_inner,
            out,
        );
    });
}

/// Descend into a nested deployment whose template is authored inline.
///
/// When the nested deployment uses `scope: "inner"` it gets a fresh scope
/// derived from its own parameters overlaid with what the parent template
/// forwards; `scope: "outer"` reuses the parent scope. LanguageVersion 2.0
/// nested templates forbid `outer` explicitly.
pub(super) fn collect_nested_logic_workflow_resource_definitions<'a>(
    resource: &'a json_spanned_value::spanned::Value,
    resource_pointer: &str,
    template: &'a json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    current_template_defaults_to_inner: bool,
    out: &mut Vec<WorkflowDefinitionCandidate<'a>>,
) {
    let template_pointer = nested_template_pointer(resource_pointer);
    if nested_template_outer_scope_blocked(resource, current_template_defaults_to_inner, arm_scope)
    {
        return;
    }
    if nested_template_uses_inner_scope(resource, current_template_defaults_to_inner, arm_scope) {
        let child_values = nested_template_values(resource, template, arm_scope);
        collect_logic_workflow_resource_definitions(
            template,
            &template_pointer,
            child_values.scope(),
            out,
        );
    } else {
        collect_logic_workflow_resource_definitions(template, &template_pointer, arm_scope, out);
    }
}

/// Descend into a nested deployment whose template is itself the result of
/// materialising an ARM expression (rather than being authored inline).
///
/// `template_source` is the original spanned node so diagnostics still refer
/// to authored bytes, while `template` is the resolved copy the walker reads.
pub(super) fn collect_materialized_nested_logic_workflow_resource_definitions<'a>(
    resource: &json_spanned_value::spanned::Value,
    resource_pointer: &str,
    template_source: &'a json_spanned_value::spanned::Value,
    template: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    current_template_defaults_to_inner: bool,
    out: &mut Vec<WorkflowDefinitionCandidate<'a>>,
) {
    let template_pointer = nested_template_pointer(resource_pointer);
    if nested_template_outer_scope_blocked(resource, current_template_defaults_to_inner, arm_scope)
    {
        return;
    }
    if nested_template_uses_inner_scope(resource, current_template_defaults_to_inner, arm_scope) {
        let child_values = nested_template_values(resource, template, arm_scope);
        collect_materialized_logic_workflow_resource_definitions(
            template_source,
            template,
            &template_pointer,
            child_values.scope(),
            out,
        );
    } else {
        collect_materialized_logic_workflow_resource_definitions(
            template_source,
            template,
            &template_pointer,
            arm_scope,
            out,
        );
    }
}

pub(super) fn collect_materialized_logic_workflow_resource_definitions<'a>(
    template_source: &'a json_spanned_value::spanned::Value,
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    out: &mut Vec<WorkflowDefinitionCandidate<'a>>,
) {
    let current_template_defaults_to_inner = template_defaults_nested_scope_to_inner(value);
    for (resource_pointer, resource, resource_is_symbolic) in arm_resource_entries(value, pointer) {
        if is_skipped_arm_resource(resource, resource_is_symbolic, arm_scope) {
            continue;
        }
        if get(resource, "type")
            .and_then(as_string)
            .is_some_and(is_logic_workflow_resource_type)
        {
            if let Some(definition) = get(resource, "properties").and_then(|v| get(v, "definition"))
            {
                let materialized_from_arm =
                    materialized_arm_value_from_spanned(definition, arm_scope);
                if let Some(materialized) = materialized_from_arm.or_else(|| {
                    to_json_value(definition).and_then(|value| spanned_from_json(&value))
                }) {
                    out.push(WorkflowDefinitionCandidate {
                        value: template_source,
                        materialized: Some(materialized),
                        value_is_definition_source: false,
                        arm_values: StaticArmValues::from_scope(arm_scope),
                        pointer: pointer_join(
                            &pointer_join(&resource_pointer, "properties"),
                            "definition",
                        ),
                        kind: get(resource, "kind").and_then(as_string).map(str::to_owned),
                        kind_invalid_type: get(resource, "kind")
                            .filter(|kind| as_string(kind).is_none())
                            .map(|kind| (pointer_join(&resource_pointer, "kind"), span(kind))),
                    });
                }
            }
            continue;
        }

        if let Some(template) = nested_template(resource) {
            let template_pointer = nested_template_pointer(&resource_pointer);
            if nested_template_uses_inner_scope(
                resource,
                current_template_defaults_to_inner,
                arm_scope,
            ) {
                let child_values = nested_template_values(resource, template, arm_scope);
                collect_materialized_logic_workflow_resource_definitions(
                    template_source,
                    template,
                    &template_pointer,
                    child_values.scope(),
                    out,
                );
            } else {
                collect_materialized_logic_workflow_resource_definitions(
                    template_source,
                    template,
                    &template_pointer,
                    arm_scope,
                    out,
                );
            }
        } else if let Some((_nested_source, template)) =
            materialized_nested_template(resource, arm_scope)
        {
            collect_materialized_nested_logic_workflow_resource_definitions(
                resource,
                &resource_pointer,
                template_source,
                &template,
                arm_scope,
                current_template_defaults_to_inner,
                out,
            );
        }
    }
}
