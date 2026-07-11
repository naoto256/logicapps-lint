//! Build and manipulate the statically-known ARM scope.
//!
//! Only ARM values that can be evaluated without runtime deployment context
//! are recorded. Anything opaque (a `reference()`, a copy input we can't
//! resolve, a parent-scope expression that fails to bind) is dropped so
//! callers treat it as unknown rather than a stale default.
use super::*;

impl StaticArmValues {
    /// Fold parent-supplied `properties.parameters` into an `inner`-scoped
    /// nested template's own scope. Entries that reference something the
    /// parent could not resolve are removed (better silent than misleading);
    /// `reference` entries are treated as opaque and drop the parameter.
    pub(super) fn overlay_deployment_parameters(
        &mut self,
        resource: &json_spanned_value::spanned::Value,
        parent_scope: crate::arm::ArmStaticScope<'_>,
    ) {
        let Some(parameters) =
            get(resource, "properties").and_then(|properties| get(properties, "parameters"))
        else {
            return;
        };
        let Some(parameters) = materialized_json_value_or_json_string(parameters, parent_scope)
            .and_then(|value| value.as_object().cloned())
        else {
            return;
        };

        for (name, parameter) in parameters {
            if parameter.get("reference").is_some() {
                self.parameters.remove(&name);
                continue;
            }
            let Some(value) = parameter
                .get("value")
                .or_else(|| parameter.get("expression"))
            else {
                continue;
            };
            if unresolved_parent_expression(value, parent_scope) {
                self.parameters.remove(&name);
                continue;
            }
            self.parameters.insert(name, value.clone());
        }
    }
}

/// Extract every statically-resolvable ARM scope element from a template
/// body: parameter defaults, variable literals, `copy` variable arrays, and
/// user-defined function outputs. Returns `None` when the template has no
/// static content worth carrying.
pub(super) fn static_arm_values(
    value: &json_spanned_value::spanned::Value,
) -> Option<StaticArmValues> {
    let mut values = StaticArmValues::default();
    if let Some(parameters) = get(value, "parameters") {
        let object = as_object(parameters)?;
        for (name, parameter) in object {
            if let Some(parameter_type) = get(parameter, "type").and_then(as_string) {
                values.parameter_types.insert(
                    name.to_string(),
                    serde_json::Value::String(parameter_type.to_owned()),
                );
            }
            let Some(value) = static_arm_parameter_value(parameter) else {
                continue;
            };
            values.parameters.insert(name.to_string(), value);
        }
    }
    collect_static_arm_functions(value, &mut values.functions);
    if let Some(variables) = get(value, "variables") {
        let object = as_object(variables)?;
        for (name, value) in object {
            if name.as_str() != "copy" {
                values
                    .variables
                    .insert(name.to_string(), to_json_value(value)?);
            }
        }
        if let Some(copy) = get(variables, "copy") {
            collect_static_variable_copies(copy, &mut values);
        }
    }
    (!values.is_empty()).then_some(values)
}

fn collect_static_arm_functions(
    template: &json_spanned_value::spanned::Value,
    functions: &mut crate::arm::ArmFunctions,
) {
    let Some(namespaces) = get(template, "functions").and_then(|value| value.as_span_array())
    else {
        return;
    };
    for namespace in namespaces.iter() {
        let Some(namespace_name) = get(namespace, "namespace").and_then(as_string) else {
            continue;
        };
        let Some(members) = get(namespace, "members").and_then(as_object) else {
            continue;
        };
        for (member_name, member) in members {
            let Some(parameters) =
                get(member, "parameters").and_then(|value| value.as_span_array())
            else {
                continue;
            };
            let Some(parameter_names) = parameters
                .iter()
                .map(|parameter| {
                    get(parameter, "name")
                        .and_then(as_string)
                        .map(str::to_owned)
                })
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            let Some(output) = get(member, "output")
                .and_then(|output| get(output, "value"))
                .and_then(to_json_value)
            else {
                continue;
            };
            functions.insert(
                format!("{namespace_name}.{member_name}").to_ascii_lowercase(),
                crate::arm::ArmFunctionDefinition {
                    parameter_names,
                    output,
                },
            );
        }
    }
}

fn collect_static_variable_copies(
    copy: &json_spanned_value::spanned::Value,
    values: &mut StaticArmValues,
) {
    let Some(copies) = copy.as_span_array() else {
        return;
    };
    for copy in copies.iter() {
        let Some(name) = get(copy, "name").and_then(as_string) else {
            continue;
        };
        let Some(count) = static_arm_copy_count(copy, values.scope()) else {
            continue;
        };
        let Some(input) = get(copy, "input") else {
            continue;
        };

        let mut expanded = Vec::with_capacity(count as usize);
        let mut complete = true;
        for index in 0..count {
            let copy_index = crate::arm::ArmCopyIndex {
                name: name.to_owned(),
                index,
            };
            let scope = values.scope().with_copy_index(&copy_index);
            let Some(value) = materialized_json_value(input, scope) else {
                complete = false;
                break;
            };
            expanded.push(value);
        }
        if complete {
            values
                .variables
                .insert(name.to_owned(), serde_json::Value::Array(expanded));
        }
    }
}

/// Statically resolve a `copy.count`, capped to a safety limit so we cannot
/// be tricked into materialising thousands of nested scopes on a large
/// authored value.
pub(super) fn static_arm_copy_count(
    copy: &json_spanned_value::spanned::Value,
    scope: crate::arm::ArmStaticScope<'_>,
) -> Option<i64> {
    const MAX_STATIC_ITERATIONS: i64 = 800;

    get(copy, "count")
        .and_then(|count| materialized_json_value(count, scope))
        .and_then(|count| count.as_i64())
        .filter(|count| (0..=MAX_STATIC_ITERATIONS).contains(count))
}

pub(super) fn static_arm_parameter_value(
    parameter: &json_spanned_value::spanned::Value,
) -> Option<serde_json::Value> {
    if let Some(default_value) = get(parameter, "defaultValue") {
        return to_json_value(default_value);
    }
    None
}

pub(super) fn materialized_arm_value_from_spanned(
    value: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> Option<json_spanned_value::spanned::Value> {
    spanned_from_json(&materialized_json_value(value, arm_scope)?)
}

pub(super) fn materialized_json_value(
    value: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> Option<serde_json::Value> {
    crate::arm::materialize_static_expressions_with_scope(to_json_value(value)?, arm_scope)
}

/// Same as `materialized_json_value`, plus a JSON-in-string fallback: some
/// ARM authors stash a whole template as a stringified JSON object (via
/// `string()` / concat tricks). Parse those back into a value so nested
/// templates authored that way still walk correctly.
pub(super) fn materialized_json_value_or_json_string(
    value: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> Option<serde_json::Value> {
    let value = materialized_json_value(value, arm_scope)?;
    match value {
        serde_json::Value::String(text) => serde_json::from_str(&text).ok(),
        value => Some(value),
    }
}

pub(super) fn unresolved_parent_expression(
    value: &serde_json::Value,
    parent_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    crate::arm::is_full_expression(text)
        && crate::arm::static_expression_value_with_scope(text, parent_scope).is_none()
}

pub(super) fn is_arm_full_expression_value(value: &json_spanned_value::spanned::Value) -> bool {
    as_string(value).is_some_and(is_arm_full_expression)
}

pub(super) fn is_arm_full_expression(text: &str) -> bool {
    crate::arm::is_full_expression(text)
}
