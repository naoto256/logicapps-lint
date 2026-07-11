//! Helpers for the "materialize an opaque ARM expression, then re-run rules
//! on the resulting value" pattern.
//!
//! Values authored as `"[expression(...)]"` are opaque at the WDL layer:
//! the workflow engine sees a string, but the ARM engine will substitute a
//! real value at deploy time. Naively running shape rules on the string
//! produces spurious `must be object` / `must be array` diagnostics, so
//! rules skip opaque nodes in place and defer to this module to (a) attempt
//! static ARM evaluation, (b) re-run the rule against the resolved value,
//! then (c) rebind every produced diagnostic's span to the original ARM
//! source location via [`extend_materialized_diagnostics`] — otherwise the
//! offsets would point into an ephemeral value the user never wrote.

use super::*;

/// Materialize `value` to a JSON object and return it with the source span of
/// the original ARM expression, or `None` if it does not statically resolve
/// to an object.
pub(super) fn static_json_object_from_spanned(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
) -> Option<(serde_json::Map<String, serde_json::Value>, ByteSpan)> {
    let (value, source_span) = static_json_value_from_spanned(file, value)?;
    let serde_json::Value::Object(object) = value else {
        return None;
    };
    Some((object, source_span))
}

/// Resolve a partial ARM object expression — the shape `"[expr]"` string
/// whose result is known to include some but not necessarily all keys — into
/// the entries we can statically determine. Rules use this to validate what
/// is present without complaining about what is missing.
pub(super) fn partial_static_json_object_from_spanned(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    if !file_allows_arm_expressions(file) {
        return None;
    }
    let text = as_string(value)?;
    Some(
        crate::arm::static_expression_object_entries_with_scope(text, arm_scope)?
            .into_iter()
            .collect(),
    )
}

/// `serde_json` counterpart to [`partial_static_json_object_from_spanned`]
/// for cases where the caller has already lost the spanned value.
pub(super) fn partial_static_json_object_from_json(
    value: &serde_json::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let text = value.as_str()?;
    Some(
        crate::arm::static_expression_object_entries_with_scope(text, arm_scope)?
            .into_iter()
            .collect(),
    )
}

/// Materialize `value` under the default (empty) ARM scope.
pub(super) fn static_json_value_from_spanned(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
) -> Option<(serde_json::Value, ByteSpan)> {
    static_json_value_from_spanned_with_scope(file, value, crate::arm::ArmStaticScope::default())
}

/// Materialize `value` under `arm_scope` (parameters/variables from the
/// enclosing ARM template). Returns the resolved value plus the source span
/// of the original expression, or `None` if the value is not a
/// statically-resolvable ARM string.
pub(super) fn static_json_value_from_spanned_with_scope(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> Option<(serde_json::Value, ByteSpan)> {
    if !file_allows_arm_expressions(file) {
        return None;
    }
    let text = as_string(value)?;
    let source_span = span(value);
    crate::arm::static_expression_value_with_scope(text, arm_scope).map(|value| {
        let value = crate::arm::materialize_static_expressions_with_scope(value.clone(), arm_scope)
            .unwrap_or(value);
        (value, source_span)
    })
}

/// Resolve `value` to a plain string. Literal strings pass through; full ARM
/// expressions are statically evaluated. `None` means the value is not a
/// string or its expression does not statically resolve.
pub(super) fn static_string_from_spanned(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
) -> Option<String> {
    let text = as_string(value)?;
    if crate::arm::is_full_expression(text) {
        if !file_allows_arm_expressions(file) {
            return None;
        }
        crate::arm::static_expression_string(text)
    } else {
        Some(text.to_owned())
    }
}

/// Whether `value` is an ARM expression the static evaluator gave up on.
/// Rules use this to suppress downstream diagnostics that would otherwise
/// fire on the opaque string form.
pub(super) fn unresolved_arm_expression_from_spanned(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
) -> bool {
    is_opaque_arm_expression(file, value)
        && as_string(value).is_some_and(|text| {
            crate::arm::is_full_expression(text)
                && crate::arm::static_expression_value(text).is_none()
        })
}

/// Like [`unresolved_arm_expression_from_spanned`] but restricted to
/// expressions whose result type could plausibly be an array. Rules that
/// only care about array-shaped inputs use this to avoid suppressing
/// diagnostics on expressions that definitely resolve to non-arrays.
pub(super) fn unresolved_arm_array_expression_from_spanned(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    is_opaque_arm_expression(file, value)
        && as_string(value).is_some_and(|text| {
            crate::arm::is_full_expression(text)
                && crate::arm::static_expression_value(text).is_none()
                && arm_expression_may_resolve_to_array(text, arm_scope)
        })
}

/// `serde_json` counterpart to [`static_string_from_spanned`].
pub(super) fn static_string_from_json(value: &serde_json::Value) -> Option<String> {
    let text = value.as_str()?;
    if crate::arm::is_full_expression(text) {
        crate::arm::static_expression_string(text)
    } else {
        Some(text.to_owned())
    }
}

/// `serde_json` counterpart to [`unresolved_arm_expression_from_spanned`].
pub(super) fn unresolved_arm_expression_from_json(
    file: &JsonFile,
    value: &serde_json::Value,
) -> bool {
    file_allows_arm_expressions(file)
        && value.as_str().is_some_and(|text| {
            crate::arm::is_full_expression(text)
                && crate::arm::static_expression_value(text).is_none()
        })
}

/// `serde_json` counterpart to [`unresolved_arm_array_expression_from_spanned`].
pub(super) fn unresolved_arm_array_expression_from_json(
    file: &JsonFile,
    value: &serde_json::Value,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    file_allows_arm_expressions(file)
        && value.as_str().is_some_and(|text| {
            crate::arm::is_full_expression(text)
                && crate::arm::static_expression_value(text).is_none()
                && arm_expression_may_resolve_to_array(text, arm_scope)
        })
}

fn arm_expression_may_resolve_to_array(
    text: &str,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> bool {
    match crate::arm::expression_result_type(text, arm_scope) {
        Some(crate::arm::ArmValueType::Array) => true,
        Some(_) => false,
        None => true,
    }
}

/// An "optional" ARM property is treated as absent when it is either JSON
/// `null` or an ARM expression that statically resolves to `null` — ARM
/// conditionals often produce `null` to omit a field.
pub(super) fn arm_optional_property_absent(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
) -> bool {
    file_allows_arm_expressions(file)
        && (value.is_null()
            || (is_opaque_arm_expression(file, value)
                && static_json_value_from_spanned(file, value)
                    .is_some_and(|(value, _)| value.is_null())))
}

/// Same "absent" semantics as [`arm_optional_property_absent`] for values
/// already materialized into `serde_json::Value`.
pub(super) fn materialized_arm_entry_absent(file: &JsonFile, value: &serde_json::Value) -> bool {
    file_allows_arm_expressions(file) && value.is_null()
}

/// Fully materialize an ARM string into a spanned JSON value ready to be
/// re-fed into a rule. The returned span is the ARM source span so callers
/// can rebind diagnostics via [`extend_materialized_diagnostics`].
pub(super) fn materialized_spanned_value(
    value: &json_spanned_value::spanned::Value,
) -> Option<(json_spanned_value::spanned::Value, ByteSpan)> {
    let text = as_string(value)?;
    let materialized = crate::arm::static_expression_value(text)?;
    Some((spanned_value_from_json(&materialized)?, span(value)))
}

/// Round-trip a `serde_json::Value` through a serializer to produce a
/// spanned value. Spans on the result point into the ephemeral serialized
/// buffer and are meaningless to the user — callers must rebind them.
pub(super) fn spanned_value_from_json(
    value: &serde_json::Value,
) -> Option<json_spanned_value::spanned::Value> {
    let source = serde_json::to_string(value).ok()?;
    json_spanned_value::from_str(&source).ok()
}

/// Append `materialized_diagnostics` after rewriting every span to
/// `source_span`. Diagnostics emitted against a synthesized value carry
/// offsets that do not correspond to anything in the user's file; rebinding
/// them to the ARM source span anchors the report on the expression the user
/// actually wrote.
pub(super) fn extend_materialized_diagnostics(
    diagnostics: &mut Vec<Diagnostic>,
    materialized_diagnostics: Vec<Diagnostic>,
    source_span: ByteSpan,
) {
    diagnostics.extend(materialized_diagnostics.into_iter().map(|mut diagnostic| {
        diagnostic.span = Some(source_span);
        diagnostic
    }));
}
