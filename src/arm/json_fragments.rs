//! Best-effort structural extraction from raw JSON text.
//!
//! Used by the `json(...)` code path when a full `serde_json::from_str` would
//! fail — typically because the JSON string contains embedded ARM expressions
//! that are not valid JSON. We only need the top-level shape (keys, entries,
//! string leaves), so a hand-written scanner walks the bytes, skipping over
//! string literals and balanced brackets without full parsing.

use super::StaticStringFragment;
use std::collections::{BTreeMap, BTreeSet};

/// Return the set of top-level object keys in `value` treated as JSON text.
/// Returns an empty set when the text is not an object or is malformed.
pub(super) fn static_json_object_keys(value: &str) -> BTreeSet<String> {
    let bytes = value.as_bytes();
    let mut keys = BTreeSet::new();
    let mut index = skip_json_whitespace(bytes, 0);
    if bytes.get(index) != Some(&b'{') {
        return keys;
    }
    index += 1;
    let mut depth = 1usize;
    while index < bytes.len() && depth > 0 {
        index = skip_json_whitespace(bytes, index);
        if index >= bytes.len() {
            break;
        }
        if depth == 1 && matches!(bytes.get(index), Some(b',')) {
            index += 1;
            continue;
        }
        if depth == 1
            && bytes.get(index) == Some(&b'"')
            && let Some((key, end)) = json_string_literal(value, index)
        {
            let colon = skip_json_whitespace(bytes, end);
            if bytes.get(colon) == Some(&b':') {
                keys.insert(key);
                index = colon + 1;
                continue;
            }
        }
        match bytes[index] {
            b'"' => {
                let Some((_, end)) = json_string_literal(value, index) else {
                    return keys;
                };
                index = end;
            }
            b'{' | b'[' => {
                depth += 1;
                index += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            _ => index += 1,
        }
    }
    keys
}

/// Return top-level `(key, value)` entries whose values parse as JSON. Values
/// that fail to parse (e.g. contain ARM expressions) are silently skipped —
/// the caller decides what to do about missing entries.
pub(super) fn static_json_object_entries(value: &str) -> BTreeMap<String, serde_json::Value> {
    let bytes = value.as_bytes();
    let mut entries = BTreeMap::new();
    let mut index = skip_json_whitespace(bytes, 0);
    if bytes.get(index) != Some(&b'{') {
        return entries;
    }
    index += 1;
    while index < bytes.len() {
        index = skip_json_whitespace(bytes, index);
        if index >= bytes.len() || bytes.get(index) == Some(&b'}') {
            break;
        }
        if matches!(bytes.get(index), Some(b',')) {
            index += 1;
            continue;
        }
        let Some((key, end)) = json_string_literal(value, index) else {
            break;
        };
        let colon = skip_json_whitespace(bytes, end);
        if bytes.get(colon) != Some(&b':') {
            break;
        }
        let value_start = skip_json_whitespace(bytes, colon + 1);
        let Some(value_end) = json_value_end(value, value_start) else {
            break;
        };
        if let Ok(parsed) = serde_json::from_str(&value[value_start..value_end]) {
            entries.insert(key, parsed);
        }
        index = value_end;
    }
    entries
}

// Find the byte index just past a JSON value beginning at `start`.
// Strings consume through their closing quote; objects/arrays consume through
// the balanced closer; everything else runs until the next value terminator
// (comma or closing bracket) with trailing whitespace stripped.
fn json_value_end(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    match bytes.get(start)? {
        b'"' => json_string_literal(text, start).map(|(_, end)| end),
        b'{' | b'[' => {
            let mut index = start;
            let mut depth = 0usize;
            while index < bytes.len() {
                match bytes[index] {
                    b'"' => {
                        let (_, end) = json_string_literal(text, index)?;
                        index = end;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return Some(index + 1);
                        }
                    }
                    _ => {}
                }
                index += 1;
            }
            None
        }
        _ => {
            let mut index = start;
            while index < bytes.len() && !matches!(bytes[index], b',' | b'}' | b']') {
                index += 1;
            }
            let end = text[..index].trim_end().len();
            (end > start).then_some(end)
        }
    }
}

fn skip_json_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

// Consume a JSON double-quoted string starting at `start` and return the
// decoded value plus the index just past the closing quote. Backslash handling
// is delegated to `serde_json::from_str` so escape sequences match the spec.
fn json_string_literal(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut index = start + 1;
    let mut escaped = false;
    while index < bytes.len() {
        if escaped {
            escaped = false;
        } else if bytes[index] == b'\\' {
            escaped = true;
        } else if bytes[index] == b'"' {
            let end = index + 1;
            return serde_json::from_str(&text[start..end])
                .ok()
                .map(|value| (value, end));
        }
        index += 1;
    }
    None
}

/// Flatten every string leaf reachable from `value` into `out` as standalone
/// fragments (no side-extension flags — these leaves are fully materialized).
/// Used to feed a materialized JSON value into fragment-consuming callers.
pub(super) fn collect_json_string_fragments(
    value: &serde_json::Value,
    out: &mut Vec<StaticStringFragment>,
) {
    match value {
        serde_json::Value::String(value) => out.push(StaticStringFragment {
            value: value.clone(),
            can_extend_left: false,
            can_extend_right: false,
        }),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_string_fragments(value, out);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                collect_json_string_fragments(value, out);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}
