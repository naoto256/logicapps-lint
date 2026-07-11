//! WDL (Workflow Definition Language) string predicates.
//!
//! Shape rules often need to decide whether a string is a fully dynamic
//! expression (`"@expr"`), an interpolated template (`"prefix@{expr}suffix"`),
//! or a literal — and, for templates, whether the literal fragments could still
//! satisfy a shape (enum member, integer, ISO 8601 duration). These helpers
//! wrap `WdlStringValue::classify` with predicates that stay conservative:
//! when uncertain, they return "may match" so real workflows are not falsely
//! flagged.

use super::*;

/// The whole string is a single `@…` expression producing the value at runtime.
pub(super) fn wdl_string_is_full_expression(value: &str) -> bool {
    crate::wdl::WdlStringValue::classify(value).is_full_expression()
}

/// Any `@…` or `@{…}` embedding is present. A literal without expressions
/// returns false.
pub(super) fn wdl_string_has_dynamic_value(value: &str) -> bool {
    crate::wdl::WdlStringValue::classify(value).has_dynamic_value()
}

/// Could the string's runtime value equal one of `allowed`? Case-sensitive:
/// the public workflowdefinition schema enums are declared that way.
pub(super) fn wdl_string_may_match_exact(value: &str, allowed: &[&str]) -> bool {
    crate::wdl::WdlStringValue::classify(value).may_match_exact(allowed)
}

/// Case-insensitive counterpart, used where the runtime itself accepts either
/// casing (for example `contentTransfer.transferMode`).
pub(super) fn wdl_string_may_match_exact_ignore_case(value: &str, allowed: &[&str]) -> bool {
    crate::wdl::WdlStringValue::classify(value).may_match_exact_ignore_case(allowed)
}

pub(super) fn wdl_string_may_be_positive_integer(value: &str) -> bool {
    let value = crate::wdl::WdlStringValue::classify(value);
    if let Some(literal) = value.literal() {
        return literal.parse::<u64>().is_ok_and(|value| value > 0);
    }
    let Some(template) = value.template() else {
        return true;
    };
    template.literal_bytes_all(|byte| byte.is_ascii_digit())
}

pub(super) fn wdl_string_may_be_integer(value: &str) -> bool {
    let value = crate::wdl::WdlStringValue::classify(value);
    if let Some(literal) = value.literal() {
        return literal.parse::<i64>().is_ok();
    }
    let Some(template) = value.template() else {
        return true;
    };
    template.literal_bytes_all(|byte| byte.is_ascii_digit() || byte == b'-')
}

pub(super) fn wdl_string_may_be_finite_number(value: &str) -> bool {
    let value = crate::wdl::WdlStringValue::classify(value);
    if let Some(literal) = value.literal() {
        return literal
            .parse::<f64>()
            .is_ok_and(|number| number.is_finite());
    }
    let Some(template) = value.template() else {
        return true;
    };
    template.literal_bytes_all(|byte| {
        byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.' | b'e' | b'E')
    })
}

/// Could the string evaluate to an ISO 8601 duration (`PT1S`, `P1D`, ...)?
///
/// Fully literal values delegate to `is_iso8601_duration`. Templates keep the
/// answer permissive: the literal fragments must only contain characters that
/// could appear inside a duration, the static prefix must be compatible with a
/// leading `P`, and the static suffix must end on a valid unit character. Any
/// interpolated segment could still fail at runtime — the shape rule only
/// filters out impossibilities.
pub(super) fn wdl_string_may_be_iso8601_duration(value: &str) -> bool {
    let value = crate::wdl::WdlStringValue::classify(value);
    if let Some(literal) = value.literal() {
        return is_iso8601_duration(literal);
    }
    let Some(template) = value.template() else {
        return true;
    };
    if !template.literal_bytes_all(|byte| {
        byte.is_ascii_digit()
            || matches!(
                byte,
                b'P' | b'T' | b'Y' | b'M' | b'W' | b'D' | b'H' | b'S' | b'.' | b','
            )
    }) {
        return false;
    }
    let prefix = template.static_prefix();
    // The prefix must either already start with `P` or still be a strict prefix
    // of `P` (e.g. empty) so an interpolation can supply it.
    if !prefix.is_empty() && !prefix.starts_with('P') && !"P".starts_with(prefix) {
        return false;
    }
    let suffix = template.static_suffix();
    suffix.is_empty()
        || suffix
            .bytes()
            .last()
            .is_some_and(|byte| matches!(byte, b'Y' | b'M' | b'W' | b'D' | b'H' | b'S'))
}
