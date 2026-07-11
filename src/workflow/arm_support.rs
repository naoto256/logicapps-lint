//! Boundary helpers between spanned JSON and ARM-materialized values.
//!
//! Every extractor routes string-shaped fields through this module to answer
//! three questions consistently: is this literal? does it statically evaluate?
//! is it opaque? Crossing the ARM boundary loses per-leaf spans — after
//! [`static_object_from_spanned`] the caller gets a `serde_json::Value` plus
//! one shared source span covering the whole materialized subtree.

use crate::json::{as_string, span};
use json_spanned_value::spanned;

/// Materialize a static string.
///
/// Plain strings pass through; `[...]` expressions are evaluated in the scope
/// and returned only when they yield a `String`. Anything else (unresolved
/// expression, non-string result, or non-string input) yields `None`.
pub(super) fn static_string_from_spanned(
    value: &spanned::Value,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> Option<String> {
    let text = as_string(value)?;
    if crate::arm::is_full_expression(text) {
        let arm_scope = arm_scope?;
        let serde_json::Value::String(value) =
            crate::arm::static_expression_value_with_scope(text, arm_scope)?
        else {
            return None;
        };
        Some(value)
    } else {
        Some(text.to_owned())
    }
}

/// True when the value is an ARM expression whose value cannot be recovered
/// in the current scope — the caller should mark the enclosing field as
/// `has_opaque_*` and avoid emitting "missing" diagnostics for it.
pub(super) fn unresolved_arm_expression_from_spanned(
    value: &spanned::Value,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> bool {
    let Some(arm_scope) = arm_scope else {
        return false;
    };
    as_string(value).is_some_and(|text| {
        crate::arm::is_full_expression(text)
            && crate::arm::static_expression_value_with_scope(text, arm_scope).is_none()
    })
}

/// Scope-free variant of [`unresolved_arm_expression_from_spanned`] for values
/// that already crossed the ARM boundary (no `spanned` wrapper to inspect).
pub(super) fn unresolved_arm_expression_from_json(value: &serde_json::Value) -> bool {
    value.as_str().is_some_and(|text| {
        crate::arm::is_full_expression(text) && crate::arm::static_expression_value(text).is_none()
    })
}

/// Materialize an object from an ARM expression, or return `None`.
///
/// Both fully-evaluated `Object` results and partial `union(...)`-style entry
/// lists count as "static enough" — the latter lets us still see individual
/// keys when the full expression cannot be reduced. The returned span points
/// at the original expression string, so every downstream diagnostic anchors
/// at the same site.
pub(super) fn static_object_from_spanned(
    value: &spanned::Value,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> Option<(
    serde_json::Map<String, serde_json::Value>,
    crate::diagnostic::ByteSpan,
)> {
    let arm_scope = arm_scope?;
    let text = as_string(value)?;
    let object = if let Some(serde_json::Value::Object(object)) =
        crate::arm::static_expression_value_with_scope(text, arm_scope)
    {
        object
    } else {
        crate::arm::static_expression_object_entries_with_scope(text, arm_scope)?
            .into_iter()
            .collect()
    };
    Some((object, span(value)))
}

/// True when this map entry should be dropped as an ARM opt-out.
///
/// Two flavors: a literal JSON `null` (only meaningful under an ARM scope —
/// without it a null in a Standard definition is just a shape error we let
/// pass) and an ARM expression that resolves to `null`. Both are the ARM
/// idiom for conditionally omitting a child.
pub(super) fn arm_null_entry_from_spanned(
    value: &spanned::Value,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> bool {
    if value.is_null() {
        return arm_scope.is_some();
    }
    let Some(arm_scope) = arm_scope else {
        return false;
    };
    let Some(text) = as_string(value) else {
        return false;
    };
    crate::arm::is_full_expression(text)
        && crate::arm::static_expression_value_with_scope(text, arm_scope)
            .is_some_and(|value| value.is_null())
}

/// Post-materialization: any JSON null is an ARM opt-out because at this point
/// we know the tree came from an ARM-evaluated expression.
pub(super) fn arm_null_entry_from_json(value: &serde_json::Value) -> bool {
    value.is_null()
}

/// Strip the workflow's `definition_pointer` from a stored pointer to recover
/// a pointer relative to `Workflow::definition`. Pointers on the summary are
/// prefixed for diagnostic output but must be relative for `Value::pointer`.
pub(super) fn strip_prefix_pointer<'a>(pointer: &'a str, prefix: &str) -> &'a str {
    if prefix.is_empty() {
        return pointer;
    }
    pointer.strip_prefix(prefix).unwrap_or(pointer)
}
