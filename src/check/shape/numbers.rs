//! Numeric predicates for shape rules.
//!
//! The workflow JSON representation stores integers as either signed or
//! unsigned, and some fields accept an integer literal wrapped as a string
//! (for example ARM-produced concurrency limits). These helpers normalize
//! both cases.

use super::*;

/// True for JSON numbers that are exactly integers — no floats or NaN.
pub(super) fn is_integer_value(value: &json_spanned_value::spanned::Value) -> bool {
    value
        .as_number()
        .is_some_and(|number| number.is_i64() || number.is_u64())
}

/// Accept either a JSON integer or a WDL-expression string. Used for integer
/// fields (Wait interval count, Recurrence count, Batch batch size, …) where
/// the runtime evaluates a parameterized value like `@parameters('n')`; only
/// structural non-integers (booleans, objects, arrays, opaque strings) are
/// flagged. WDL classification is intentionally permissive here — the goal
/// is to skip the type check on any `@...` string, not to verify the
/// expression returns an integer.
pub(super) fn is_integer_or_wdl_expression(value: &json_spanned_value::spanned::Value) -> bool {
    if is_integer_value(value) {
        return true;
    }
    let Some(text) = as_string(value) else {
        return false;
    };
    text.starts_with('@') && !text.starts_with("@@")
}

/// Positive-integer variant of [`is_integer_or_wdl_expression`]. WDL
/// expressions are accepted without sign inspection because the value is
/// unknown until runtime — only literal non-positive integers are rejected.
pub(super) fn is_positive_integer_or_wdl_expression(
    value: &json_spanned_value::spanned::Value,
) -> bool {
    if is_positive_integer_value(value) {
        return true;
    }
    let Some(text) = as_string(value) else {
        return false;
    };
    text.starts_with('@') && !text.starts_with("@@")
}

/// Strictly greater than zero. Handles both signed and unsigned storage.
pub(super) fn is_positive_integer_value(value: &json_spanned_value::spanned::Value) -> bool {
    value.as_number().is_some_and(|number| {
        number.as_u64().is_some_and(|value| value > 0)
            || number.as_i64().is_some_and(|value| value > 0)
    })
}

/// Extract an `i64`, converting from unsigned storage when it fits.
pub(super) fn integer_value(value: &json_spanned_value::spanned::Value) -> Option<i64> {
    let number = value.as_number()?;
    number
        .as_i64()
        .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok()))
}

/// Accept either a JSON integer or a string that parses as one. Used for the
/// fields ARM commonly stringifies (retry counts, delay counts, …).
pub(super) fn integer_or_integer_string_value(
    value: &json_spanned_value::spanned::Value,
) -> Option<i64> {
    integer_value(value).or_else(|| as_string(value)?.parse::<i64>().ok())
}
