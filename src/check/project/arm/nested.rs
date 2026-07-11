//! Nested `Microsoft.Resources/deployments` handling.
//!
//! Determines whether a nested deployment has an authored template (or one
//! that materialises from a static expression), which ARM scope applies to
//! evaluations inside it (`inner` vs `outer`, with languageVersion 2.0
//! forbidding `outer`), and how the parent forwards parameter values into
//! the child. Every helper is designed so an unresolved expression stays
//! opaque rather than silently defaulting.
use super::resources::is_arm_deployment_resource_type;
use super::values::{
    materialized_json_value, materialized_json_value_or_json_string, static_arm_values,
};
use super::*;

/// The inline `properties.template` of a `Microsoft.Resources/deployments`
/// resource, when authored as an object.
pub(super) fn nested_template(
    resource: &json_spanned_value::spanned::Value,
) -> Option<&json_spanned_value::spanned::Value> {
    get(resource, "type")
        .and_then(as_string)
        .filter(|resource_type| is_arm_deployment_resource_type(resource_type))?;
    let template = get(resource, "properties").and_then(|value| get(value, "template"))?;
    as_object(template)?;
    Some(template)
}

/// The nested template obtained by materialising a `template` field that was
/// authored as an ARM expression rather than an inline object. Returns the
/// original spanned node paired with the resolved copy.
pub(super) fn materialized_nested_template<'a>(
    resource: &'a json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> Option<(
    &'a json_spanned_value::spanned::Value,
    json_spanned_value::spanned::Value,
)> {
    get(resource, "type")
        .and_then(as_string)
        .filter(|resource_type| is_arm_deployment_resource_type(resource_type))?;
    let template = get(resource, "properties").and_then(|value| get(value, "template"))?;
    if as_object(template).is_some() {
        return None;
    }
    let value = materialized_json_value_or_json_string(template, arm_scope)?;
    let object = value.as_object()?;
    spanned_from_json(&serde_json::Value::Object(object.clone())).map(|value| (template, value))
}

pub(super) fn nested_template_pointer(resource_pointer: &str) -> String {
    pointer_join(&pointer_join(resource_pointer, "properties"), "template")
}

/// Under `languageVersion: "2.0"` nested deployments default to `inner`
/// scope (and cannot opt back into `outer`). Signals both to nested scope
/// resolution and to symbolic-resource treatment.
pub(super) fn template_defaults_nested_scope_to_inner(
    value: &json_spanned_value::spanned::Value,
) -> bool {
    get(value, "languageVersion")
        .and_then(as_string)
        .is_some_and(|version| version.eq_ignore_ascii_case("2.0"))
}

pub(super) fn nested_template_uses_inner_scope(
    resource: &json_spanned_value::spanned::Value,
    current_template_defaults_to_inner: bool,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    if let Some(scope) = nested_template_explicit_scope(resource, arm_scope) {
        return scope.eq_ignore_ascii_case("inner");
    }
    current_template_defaults_to_inner
}

pub(super) fn nested_template_outer_scope_blocked(
    resource: &json_spanned_value::spanned::Value,
    current_template_defaults_to_inner: bool,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    current_template_defaults_to_inner
        && nested_template_explicit_scope(resource, arm_scope)
            .is_some_and(|scope| scope.eq_ignore_ascii_case("outer"))
}

pub(super) fn nested_template_explicit_scope(
    resource: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> Option<String> {
    let options = get(resource, "properties")
        .and_then(|properties| get(properties, "expressionEvaluationOptions"))?;
    if let Some(scope) = materialized_json_value(options, arm_scope)
        .as_ref()
        .and_then(|options| options.get("scope"))
        .and_then(serde_json::Value::as_str)
    {
        return Some(scope.to_owned());
    }
    get(options, "scope").and_then(as_string).map(str::to_owned)
}

pub(super) fn nested_template_scope_pointer(resource_pointer: &str) -> String {
    pointer_join(
        &pointer_join(
            &pointer_join(resource_pointer, "properties"),
            "expressionEvaluationOptions",
        ),
        "scope",
    )
}

pub(super) fn nested_template_scope_span(
    resource: &json_spanned_value::spanned::Value,
) -> Option<crate::diagnostic::ByteSpan> {
    get(resource, "properties")
        .and_then(|properties| get(properties, "expressionEvaluationOptions"))
        .and_then(|options| get(options, "scope").or(Some(options)))
        .map(span)
}

/// Compute the ARM scope visible inside an `inner`-scoped nested template.
/// Start from the template's own parameters/variables, then overlay any
/// parameter values the parent deployment forwards via `properties.parameters`.
pub(super) fn nested_template_values(
    resource: &json_spanned_value::spanned::Value,
    template: &json_spanned_value::spanned::Value,
    parent_scope: crate::arm::ArmStaticScope<'_>,
) -> StaticArmValues {
    let mut values = static_arm_values(template).unwrap_or_default();
    values.overlay_deployment_parameters(resource, parent_scope);
    values
}
