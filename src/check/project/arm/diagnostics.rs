//! ARM-resource shape diagnostics.
//!
//! Two responsibilities interleave: validating the ARM template's own shape
//! (resource array vs languageVersion 2.0 symbolic map, `copy` invariants,
//! nested-deployment scope rules) and validating the `Microsoft.Logic/workflows`
//! resources against their definition body (required properties, workflow
//! parameter supply). Everything runs recursively so nested deployments are
//! validated under the correct inherited scope.
use super::nested::{
    materialized_nested_template, nested_template, nested_template_outer_scope_blocked,
    nested_template_pointer, nested_template_scope_pointer, nested_template_scope_span,
    nested_template_uses_inner_scope, nested_template_values,
    template_defaults_nested_scope_to_inner,
};
use super::parameters::{arm_workflow_parameter_is_supplied, workflow_parameter_requirements};
use super::resources::{
    arm_resource_entries, for_each_arm_resource_copy_iteration, is_logic_workflow_resource_type,
    is_skipped_arm_resource, symbolic_resource_name_valid,
};
use super::values::{
    is_arm_full_expression_value, materialized_arm_value_from_spanned, materialized_json_value,
};
use super::*;

pub(super) fn collect_arm_resource_diagnostics(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let current_template_defaults_to_inner = template_defaults_nested_scope_to_inner(value);
    collect_arm_resource_diagnostics_in(
        value,
        pointer,
        arm_scope,
        current_template_defaults_to_inner,
        file,
        diagnostics,
    );
}

pub(super) fn collect_arm_resource_diagnostics_in(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    current_template_defaults_to_inner: bool,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    collect_arm_template_resource_shape_diagnostics(value, pointer, file, diagnostics);
    for (resource_pointer, resource, resource_is_symbolic) in arm_resource_entries(value, pointer) {
        collect_arm_resource_entry_diagnostics(
            resource,
            &resource_pointer,
            resource_is_symbolic,
            arm_scope,
            current_template_defaults_to_inner,
            file,
            diagnostics,
        );
    }
}

/// Validate the container shape of `resources` at the current template
/// level. Object form is only legal under `languageVersion: "2.0"` (symbolic
/// resource names); everywhere else it must be an array.
pub(super) fn collect_arm_template_resource_shape_diagnostics(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(resources) = get(value, "resources") else {
        return;
    };
    if let Some(object) = as_object(resources) {
        if !template_defaults_nested_scope_to_inner(value) {
            diagnostics.push(Diagnostic::error(
                "arm-template-invalid-shape",
                &file.path,
                pointer_join(pointer, "resources"),
                Some(span(resources)),
                "ARM template resources must be an array unless languageVersion is 2.0",
            ));
            return;
        }
        for (name, resource) in object {
            if !symbolic_resource_name_valid(name) {
                diagnostics.push(Diagnostic::error(
                    "arm-template-invalid-shape",
                    &file.path,
                    pointer_join(&pointer_join(pointer, "resources"), name),
                    Some(span(resource)),
                    format!("ARM symbolic resource name '{name}' is not supported"),
                ));
            }
        }
    } else if resources.as_span_array().is_none() {
        diagnostics.push(Diagnostic::error(
            "arm-template-invalid-shape",
            &file.path,
            pointer_join(pointer, "resources"),
            Some(span(resources)),
            "ARM template resources must be an array or a languageVersion 2.0 object",
        ));
    }
}

pub(super) fn collect_arm_resource_entry_diagnostics(
    resource: &json_spanned_value::spanned::Value,
    resource_pointer: &str,
    resource_is_symbolic: bool,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    current_template_defaults_to_inner: bool,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !validate_arm_resource_copy(resource, resource_pointer, arm_scope, file, diagnostics) {
        return;
    }
    if is_skipped_arm_resource(resource, resource_is_symbolic, arm_scope) {
        return;
    }
    if get(resource, "type")
        .and_then(as_string)
        .is_some_and(is_logic_workflow_resource_type)
    {
        collect_logic_workflow_resource_diagnostics(
            resource,
            resource_pointer,
            arm_scope,
            file,
            diagnostics,
        );
        return;
    }

    for_each_arm_resource_copy_iteration(resource, arm_scope, |iteration_scope| {
        if let Some(template) = nested_template(resource) {
            collect_nested_arm_resource_diagnostics(
                resource,
                resource_pointer,
                template,
                iteration_scope,
                current_template_defaults_to_inner,
                file,
                diagnostics,
            );
        } else if let Some((_template_source, template)) =
            materialized_nested_template(resource, iteration_scope)
        {
            collect_nested_arm_resource_diagnostics(
                resource,
                resource_pointer,
                &template,
                iteration_scope,
                current_template_defaults_to_inner,
                file,
                diagnostics,
            );
        }

        collect_arm_resource_diagnostics_in(
            resource,
            resource_pointer,
            iteration_scope,
            current_template_defaults_to_inner,
            file,
            diagnostics,
        );
    });
}

/// Enforce the `copy` block invariants (object with `name`, `count`).
/// Returns `false` when the block is malformed so the caller skips further
/// per-iteration walking that would otherwise cascade misleading errors.
fn validate_arm_resource_copy(
    resource: &json_spanned_value::spanned::Value,
    resource_pointer: &str,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) -> bool {
    let Some(copy) = get(resource, "copy") else {
        return true;
    };
    let copy_pointer = pointer_join(resource_pointer, "copy");
    if as_object(copy).is_none() {
        diagnostics.push(Diagnostic::error(
            "arm-template-invalid-shape",
            &file.path,
            copy_pointer,
            Some(span(copy)),
            "ARM resource copy must be an object",
        ));
        return false;
    }
    let Some(name) = get(copy, "name") else {
        diagnostics.push(Diagnostic::error(
            "arm-template-invalid-shape",
            &file.path,
            pointer_join(&copy_pointer, "name"),
            Some(span(copy)),
            "ARM resource copy is missing required field 'name'",
        ));
        return false;
    };
    if as_string(name).is_none() {
        diagnostics.push(Diagnostic::error(
            "arm-template-invalid-shape",
            &file.path,
            pointer_join(&copy_pointer, "name"),
            Some(span(name)),
            "ARM resource copy name must be a string",
        ));
        return false;
    }
    let Some(count) = get(copy, "count") else {
        diagnostics.push(Diagnostic::error(
            "arm-template-invalid-shape",
            &file.path,
            pointer_join(&copy_pointer, "count"),
            Some(span(copy)),
            "ARM resource copy is missing required field 'count'",
        ));
        return false;
    };
    let valid_count = match materialized_json_value(count, arm_scope) {
        Some(serde_json::Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok()))
            .is_some_and(|value| value >= 0),
        Some(_) => false,
        None => is_arm_full_expression_value(count),
    };
    if !valid_count {
        diagnostics.push(Diagnostic::error(
            "arm-template-invalid-shape",
            &file.path,
            pointer_join(&copy_pointer, "count"),
            Some(span(count)),
            "ARM resource copy count must be a non-negative integer or expression",
        ));
    }
    valid_count
}

pub(super) fn collect_nested_arm_resource_diagnostics(
    resource: &json_spanned_value::spanned::Value,
    resource_pointer: &str,
    template: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    current_template_defaults_to_inner: bool,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let template_pointer = nested_template_pointer(resource_pointer);
    if nested_template_outer_scope_blocked(resource, current_template_defaults_to_inner, arm_scope)
    {
        diagnostics.push(Diagnostic::error(
            "arm-template-invalid-shape",
            &file.path,
            nested_template_scope_pointer(resource_pointer),
            nested_template_scope_span(resource),
            "ARM languageVersion 2.0 nested deployments do not support expressionEvaluationOptions.scope 'outer'",
        ));
        return;
    }
    if nested_template_uses_inner_scope(resource, current_template_defaults_to_inner, arm_scope) {
        let child_values = nested_template_values(resource, template, arm_scope);
        collect_arm_resource_diagnostics(
            template,
            &template_pointer,
            child_values.scope(),
            file,
            diagnostics,
        );
    } else {
        collect_arm_resource_diagnostics(template, &template_pointer, arm_scope, file, diagnostics);
    }
}

/// Enforce `Microsoft.Logic/workflows` resource shape and cross-check the
/// ARM-supplied parameter object against the workflow definition's declared
/// parameters. `$connections`, defaulted parameters, and ARM-dynamic entries
/// are skipped — we only raise on parameters the user must supply but did not.
pub(super) fn collect_logic_workflow_resource_diagnostics(
    resource: &json_spanned_value::spanned::Value,
    resource_pointer: &str,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let properties_pointer = pointer_join(resource_pointer, "properties");
    let Some(properties) = get(resource, "properties") else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            properties_pointer,
            Some(span(resource)),
            "Microsoft.Logic/workflows resource is missing required object field 'properties'",
        ));
        return;
    };
    let Some(definition) = get(properties, "definition") else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(&properties_pointer, "definition"),
            Some(span(properties)),
            "Microsoft.Logic/workflows properties is missing required object field 'definition'",
        ));
        return;
    };
    let definition_pointer = pointer_join(&properties_pointer, "definition");
    let supplied_parameters_value = get(properties, "parameters");
    let mut supplied_parameters_dynamic = false;
    let materialized_supplied_parameters: Option<json_spanned_value::spanned::Value>;
    // Static sibling parameters can be validated even when the definition body
    // itself is ARM-dynamic.
    let supplied_parameters = if let Some(value) = supplied_parameters_value {
        let parameters_value = if is_arm_full_expression_value(value) {
            materialized_supplied_parameters =
                materialized_arm_value_from_spanned(value, arm_scope);
            match materialized_supplied_parameters.as_ref() {
                Some(value) if is_arm_full_expression_value(value) => {
                    supplied_parameters_dynamic = true;
                    None
                }
                Some(value) => Some(value),
                None => {
                    supplied_parameters_dynamic = true;
                    None
                }
            }
        } else {
            Some(value)
        };
        if let Some(parameters_value) = parameters_value {
            if parameters_value.is_null() {
                None
            } else {
                let Some(object) = as_object(parameters_value) else {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-invalid-type",
                        &file.path,
                        pointer_join(&properties_pointer, "parameters"),
                        Some(span(value)),
                        "Microsoft.Logic/workflows properties.parameters must be an object",
                    ));
                    return;
                };
                Some(object)
            }
        } else {
            None
        }
    } else {
        None
    };

    let materialized_definition;
    let definition_for_checks = if is_arm_full_expression_value(definition) {
        let Some(value) = materialized_arm_value_from_spanned(definition, arm_scope) else {
            return;
        };
        if is_arm_full_expression_value(&value) {
            return;
        }
        materialized_definition = value;
        &materialized_definition
    } else {
        definition
    };
    if as_object(definition_for_checks).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            definition_pointer,
            Some(span(definition)),
            "Microsoft.Logic/workflows properties.definition must be an object",
        ));
        return;
    }
    // If ARM supplies the whole parameter object, individual missing-parameter
    // checks would be pure speculation.
    if supplied_parameters_dynamic {
        return;
    }

    let Some(definition_parameters) =
        workflow_parameter_requirements(definition_for_checks, &definition_pointer, arm_scope)
    else {
        return;
    };
    for parameter in definition_parameters {
        // `$connections`, dynamic ARM parameter entries, and defaulted workflow
        // parameters do not require a corresponding `properties.parameters` value.
        if !parameter.requires_value {
            continue;
        }
        if supplied_parameters.is_some_and(|parameters| {
            parameters
                .get(parameter.name.as_str())
                .is_some_and(|value| arm_workflow_parameter_is_supplied(value, arm_scope))
        }) {
            continue;
        }
        diagnostics.push(Diagnostic::error(
            "arm-missing-workflow-parameter",
            &file.path,
            parameter.pointer,
            Some(parameter.span),
            format!(
                "Microsoft.Logic/workflows properties.parameters does not supply workflow parameter '{}'",
                parameter.name
            ),
        ));
    }
}
