//! Extract statically resolvable WDL references from a JSON string value.
//!
//! Only calls whose first argument is a literal string are captured — a
//! call like `outputs(variables('x'))` is silently ignored because the
//! target cannot be resolved without evaluation and reporting it would
//! produce false positives. Reference kinds are only assigned to helpers
//! the linter can validate against workflow state.

use super::lex::{first_string_arg, next_call};
use super::segments::{find_interpolation_end, find_next_interpolation_start};
use super::{Reference, ReferenceKind};

/// Extract every statically resolvable reference from `text`.
///
/// Callers (mainly `src/check/references.rs`) feed in raw JSON string
/// values. A leading `@` (that is not `@@` or `@{`) means the whole string
/// is one expression; otherwise the string is plain text with zero or more
/// `@{...}` interpolations. Both shapes are handled here.
pub fn references_in_string(text: &str) -> Vec<Reference> {
    let mut refs = Vec::new();
    let bytes = text.as_bytes();

    // A JSON string is WDL only when it starts with @..., except interpolation
    // segments @{} which can appear inside ordinary strings. Treating every @
    // as an expression start would lint literal text and create noisy false
    // positives.
    if bytes.first() == Some(&b'@') && !bytes.starts_with(b"@@") && !bytes.starts_with(b"@{") {
        extract_calls(&text[1..], &mut refs);
        return refs;
    }

    // Skip the leading `@@` so a doubled escape at position 0 does not fool
    // the interpolation finder into treating the next `@{` as escaped too.
    let mut index = if bytes.starts_with(b"@@") { 2 } else { 0 };
    while let Some(at) = find_next_interpolation_start(bytes, index) {
        if bytes.get(at + 1) == Some(&b'@') {
            index = at + 2;
            continue;
        }

        if bytes.get(at + 1) == Some(&b'{') {
            let Some(end) = find_interpolation_end(text, at + 2) else {
                break;
            };
            extract_calls(&text[at + 2..end], &mut refs);
            index = end + 1;
            continue;
        }

        index = at + 1;
    }

    refs
}

/// Collect references from a single expression body (no `@` or `@{...}`
/// wrapping). Case-sensitive matching is intentional here: the helper name
/// table below uses the canonical Logic Apps casing, and case-insensitive
/// matching is applied at the check layer where the workflow state is also
/// normalized.
fn extract_calls(expr: &str, refs: &mut Vec<Reference>) {
    let mut index = 0;
    while index < expr.len() {
        let Some((name, args_start)) = next_call(expr, index) else {
            break;
        };
        if name == "item" {
            // `item()` binds to the enclosing foreach / data-operation scope
            // and takes no name argument; the check layer supplies the scope.
            refs.push(Reference {
                kind: ReferenceKind::CurrentItem,
                name: String::new(),
            });
        } else if let Some(kind) = reference_kind(name)
            && let Some(arg) = first_string_arg(expr, args_start + 1)
        {
            refs.push(Reference { kind, name: arg });
        }
        index = args_start + 1;
    }
}

/// Map a WDL helper name to the workflow namespace it targets. Only helpers
/// this linter can validate are listed; unknown helpers yield `None` so the
/// caller quietly skips them.
fn reference_kind(name: &str) -> Option<ReferenceKind> {
    match name {
        "actions"
        | "body"
        | "formDataMultiValues"
        | "formDataValue"
        | "multipartBody"
        | "outputs" => Some(ReferenceKind::Action),
        "result" => Some(ReferenceKind::ScopedAction),
        "iterationIndexes" => Some(ReferenceKind::UntilLoop),
        "variables" => Some(ReferenceKind::Variable),
        "parameters" => Some(ReferenceKind::Parameter),
        "items" => Some(ReferenceKind::Item),
        _ => None,
    }
}
