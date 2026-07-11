//! Enumerate every string leaf in a value tree.
//!
//! Two flavors: [`string_sites`] returns the literal JSON string leaves, and
//! [`string_sites_with_arm_static`] additionally emits synthetic sites for
//! anything that can be materialized from an ARM `[...]` expression. The
//! synthetic sites carry `arm_static = true` and, when only fragments of the
//! expression can be recovered, `arm_partial = true` with directional flags
//! so callers know matches may extend beyond the fragment boundaries.

use super::*;
use crate::json::{as_object, as_string, pointer_join, span};
use json_spanned_value::spanned;
use std::borrow::Cow;

/// Every string leaf in `value`, tagged with its JSON pointer and source span.
/// No ARM interpretation — expressions are returned as their raw string form.
pub fn string_sites<'a>(value: &'a spanned::Value, pointer: &str) -> Vec<StringSite<'a>> {
    let mut sites = Vec::new();
    collect_strings(value, pointer, &mut sites);
    sites
}

/// Like [`string_sites`], but also emits synthetic sites for strings hidden
/// inside statically-evaluable ARM expressions — including partial fragments
/// pulled from expressions that only reduce in pieces. Used by WDL reference
/// checks so that `outputs('X')` inside `[concat(...)]` is still visible.
pub fn string_sites_with_arm_static<'a>(
    value: &'a spanned::Value,
    pointer: &str,
    arm_scope: crate::arm::ArmStaticScope<'_>,
) -> Vec<StringSite<'a>> {
    let mut sites = Vec::new();
    collect_strings_with_arm_static(value, pointer, arm_scope, &mut sites);
    sites
}

fn collect_strings<'a>(value: &'a spanned::Value, pointer: &str, out: &mut Vec<StringSite<'a>>) {
    if let Some(text) = as_string(value) {
        out.push(StringSite {
            value: Cow::Borrowed(text),
            pointer: pointer.to_owned(),
            span: span(value),
            arm_static: false,
            arm_partial: false,
            arm_partial_can_extend_left: false,
            arm_partial_can_extend_right: false,
        });
        return;
    }

    if let Some(object) = as_object(value) {
        for (key, child) in object.iter() {
            collect_strings(child, &pointer_join(pointer, key), out);
        }
        return;
    }

    if let Some(array) = value.as_span_array() {
        for (index, child) in array.iter().enumerate() {
            collect_strings(child, &pointer_join(pointer, &index.to_string()), out);
        }
    }
}

fn collect_strings_with_arm_static<'a>(
    value: &'a spanned::Value,
    pointer: &str,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    out: &mut Vec<StringSite<'a>>,
) {
    if let Some(text) = as_string(value) {
        if crate::arm::is_full_expression(text) {
            let source_span = span(value);
            if let Some(static_value) =
                crate::arm::static_expression_value_with_scope(text, arm_scope)
            {
                collect_materialized_or_partial_strings(
                    &static_value,
                    pointer,
                    source_span,
                    arm_scope,
                    out,
                );
            } else {
                // Expression did not reduce fully. Special-case `union(...)`:
                // key/value pairs can still be enumerated even when the merged
                // object cannot be materialized as one value.
                if full_arm_expression_calls(text, "union")
                    && let Some(static_entries) =
                        crate::arm::static_expression_object_entries_with_scope(text, arm_scope)
                {
                    let static_value =
                        serde_json::Value::Object(static_entries.into_iter().collect());
                    collect_json_strings(&static_value, pointer, source_span, out);
                }
                // Emit any string fragments recovered from the expression as
                // partial sites so WDL reference matching still fires on them.
                for fragment in
                    crate::arm::static_expression_string_fragments_with_scope(text, arm_scope)
                {
                    out.push(StringSite {
                        value: Cow::Owned(fragment.value),
                        pointer: pointer.to_owned(),
                        span: source_span,
                        arm_static: true,
                        arm_partial: true,
                        arm_partial_can_extend_left: fragment.can_extend_left,
                        arm_partial_can_extend_right: fragment.can_extend_right,
                    });
                }
                // Last resort: an unresolvable expression that still contains
                // an unquoted `@{...}` WDL payload. Surface the original text
                // so WDL rules can flag the embedded reference.
                if crate::arm::full_expression_contains_unquoted_wdl(text) {
                    out.push(StringSite {
                        value: Cow::Borrowed(text),
                        pointer: pointer.to_owned(),
                        span: source_span,
                        arm_static: true,
                        arm_partial: false,
                        arm_partial_can_extend_left: false,
                        arm_partial_can_extend_right: false,
                    });
                }
            }
        } else {
            out.push(StringSite {
                value: Cow::Borrowed(text),
                pointer: pointer.to_owned(),
                span: span(value),
                arm_static: false,
                arm_partial: false,
                arm_partial_can_extend_left: false,
                arm_partial_can_extend_right: false,
            });
        }
        return;
    }

    if let Some(object) = as_object(value) {
        for (key, child) in object.iter() {
            collect_strings_with_arm_static(child, &pointer_join(pointer, key), arm_scope, out);
        }
        return;
    }

    if let Some(array) = value.as_span_array() {
        for (index, child) in array.iter().enumerate() {
            collect_strings_with_arm_static(
                child,
                &pointer_join(pointer, &index.to_string()),
                arm_scope,
                out,
            );
        }
    }
}

/// Walk a materialized ARM value, preferring full materialization but handling
/// the case where the leaf is itself another `[...]` expression (nested ARM).
fn collect_materialized_or_partial_strings<'a>(
    value: &serde_json::Value,
    pointer: &str,
    source_span: crate::diagnostic::ByteSpan,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    out: &mut Vec<StringSite<'a>>,
) {
    let Some(text) = value.as_str() else {
        collect_json_strings(value, pointer, source_span, out);
        return;
    };
    if crate::arm::is_full_expression(text) {
        if let Some(static_entries) =
            crate::arm::static_expression_object_entries_with_scope(text, arm_scope)
        {
            let static_value = serde_json::Value::Object(static_entries.into_iter().collect());
            collect_json_strings(&static_value, pointer, source_span, out);
        } else if crate::arm::full_expression_contains_unquoted_wdl(text) {
            collect_json_strings(value, pointer, source_span, out);
        }
        return;
    }
    collect_json_strings(value, pointer, source_span, out);
}

/// Cheap syntactic check: is `text` a `[<function_name>(...)]` expression?
/// `[[...]` is ARM's literal-bracket escape and must not match.
fn full_arm_expression_calls(text: &str, function_name: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.starts_with("[[") {
        return false;
    }
    let Some(inner) = trimmed
        .strip_prefix('[')
        .and_then(|text| text.strip_suffix(']'))
        .map(str::trim)
    else {
        return false;
    };
    let Some(open) = inner.find('(') else {
        return false;
    };
    inner[..open].trim().eq_ignore_ascii_case(function_name)
}

fn collect_json_strings<'a>(
    value: &serde_json::Value,
    pointer: &str,
    source_span: crate::diagnostic::ByteSpan,
    out: &mut Vec<StringSite<'a>>,
) {
    match value {
        serde_json::Value::String(text) => out.push(StringSite {
            value: Cow::Owned(text.clone()),
            pointer: pointer.to_owned(),
            span: source_span,
            arm_static: true,
            arm_partial: false,
            arm_partial_can_extend_left: false,
            arm_partial_can_extend_right: false,
        }),
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_json_strings(
                    value,
                    &pointer_join(pointer, &index.to_string()),
                    source_span,
                    out,
                );
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                collect_json_strings(value, &pointer_join(pointer, key), source_span, out);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_arm_json_string_keeps_wdl_payload() {
        let value =
            json_spanned_value::from_str("\"[json('\\\"[concat(@{outputs(''Missing'')})]\\\"')]\"")
                .expect("fixture string parses");

        let sites =
            string_sites_with_arm_static(&value, "/inputs", crate::arm::ArmStaticScope::default());

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].value, "[concat(@{outputs('Missing')})]");
        assert!(sites[0].arm_static);
        assert!(!sites[0].arm_partial);
        assert_eq!(
            crate::wdl::references_in_string(sites[0].value.as_ref()).len(),
            1
        );
        assert_eq!(
            crate::wdl::references_in_string("[json('\\\"[concat(@{outputs(''Missing'')})]\\\"')]")
                .len(),
            1
        );
    }
}
