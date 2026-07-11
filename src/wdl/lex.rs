//! Low-level lexing primitives shared by the WDL scanner submodules.
//!
//! Everything here operates on raw bytes for speed: WDL identifiers are
//! ASCII, and the callers only need byte offsets. Multibyte content only
//! appears inside string literals, which are copied out as `&str`/`String`
//! slices at UTF-8 boundaries — so the byte-oriented state machine is safe
//! even for non-ASCII payloads (e.g. Japanese action names).

/// Identify a call at the very start of an expression body.
///
/// Returns `(identifier, index_of_open_paren)` when the leading identifier
/// is immediately followed (possibly after whitespace) by `(`. Used by the
/// root-expression suffix check to locate the top-level call whose
/// accessors are being validated.
pub(super) fn call_at_expression_start(expr: &str) -> Option<(&str, usize)> {
    let bytes = expr.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if index >= bytes.len() || !is_ident_start(bytes[index]) {
        return None;
    }
    let start = index;
    index += 1;
    while index < bytes.len() && is_ident_continue(bytes[index]) {
        index += 1;
    }
    let name = &expr[start..index];
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    (bytes.get(index) == Some(&b'(')).then_some((name, index))
}

/// Advance past a balanced `open`/`close` pair, returning the index one
/// past the matching closer. String literals are transparently skipped so
/// a stray `)` inside `'...'` does not close the group. Returns `None` on
/// unbalanced input, which callers treat as a syntax bail-out rather than a
/// panic-worthy error.
pub(super) fn consume_balanced(
    expr: &str,
    open_index: usize,
    open: u8,
    close: u8,
) -> Option<usize> {
    let bytes = expr.as_bytes();
    if bytes.get(open_index) != Some(&open) {
        return None;
    }
    let mut depth = 1usize;
    let mut index = open_index + 1;
    while index < bytes.len() {
        if bytes[index] == b'\'' {
            index = skip_string_literal(bytes, index)?;
            continue;
        }
        if bytes[index] == open {
            depth += 1;
        } else if bytes[index] == close {
            depth -= 1;
            if depth == 0 {
                return Some(index + 1);
            }
        }
        index += 1;
    }
    None
}

/// Return the leading identifier of a root expression together with the
/// index one past its last byte, or `None` when the expression does not
/// start with an identifier. Unlike `call_at_expression_start`, this does
/// not require a following `(` — it is used to detect bare-identifier root
/// forms such as `@variables`.
pub(super) fn root_expression_identifier_with_end(expr: &str) -> Option<(&str, usize)> {
    let bytes = expr.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if index >= bytes.len() || !is_ident_start(bytes[index]) {
        return None;
    }
    let start = index;
    index += 1;
    while index < bytes.len() && is_ident_continue(bytes[index]) {
        index += 1;
    }
    Some((&expr[start..index], index))
}

/// Whether `open` and `close` form a matching bracket pair.
pub(super) fn delimiters_match(open: u8, close: u8) -> bool {
    matches!((open, close), (b'(', b')') | (b'[', b']') | (b'{', b'}'))
}

/// Find the next `identifier(` pair at or after `from`, skipping string
/// literals so identifiers inside quoted text are never reported as calls.
/// Double-quoted literals are also skipped — WDL forbids them, but authors
/// occasionally write JSON-style strings and we do not want the scanner to
/// misclassify their contents.
pub(super) fn next_call(expr: &str, from: usize) -> Option<(&str, usize)> {
    let bytes = expr.as_bytes();
    let mut index = from;
    while index < bytes.len() {
        if bytes[index] == b'\'' {
            index = skip_string_literal(bytes, index).unwrap_or(bytes.len());
            continue;
        }
        if bytes[index] == b'"' {
            index = skip_double_quoted_literal(bytes, index).unwrap_or(bytes.len());
            continue;
        }
        if is_ident_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_ident_continue(bytes[index]) {
                index += 1;
            }
            let name = &expr[start..index];
            let mut cursor = index;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if bytes.get(cursor) == Some(&b'(') {
                return Some((name, cursor));
            }
        }
        index += 1;
    }
    None
}

/// Skip over a `"..."` literal, honoring backslash escapes. Only used
/// defensively to avoid mis-scanning identifiers inside JSON-style strings.
fn skip_double_quoted_literal(bytes: &[u8], from: usize) -> Option<usize> {
    let mut index = from + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index = (index + 2).min(bytes.len()),
            b'"' => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}

/// Skip over a `'...'` WDL string literal starting at `from`, returning the
/// index one past the closing quote. In WDL, `''` inside a literal is an
/// escaped single quote — the pair is consumed as part of the literal,
/// not treated as end-then-start.
pub(super) fn skip_string_literal(bytes: &[u8], from: usize) -> Option<usize> {
    let mut index = from + 1;
    while index < bytes.len() {
        if bytes[index] == b'\'' {
            if bytes.get(index + 1) == Some(&b'\'') {
                index += 2;
                continue;
            }
            return Some(index + 1);
        }
        index += 1;
    }
    None
}

/// Decode the first argument of a call as a WDL string literal, unescaping
/// doubled quotes. Returns `None` when the first argument is not a literal
/// (e.g. it is another call or bracket accessor) — reference extraction
/// then skips the call because we cannot resolve its target statically.
pub(super) fn first_string_arg(expr: &str, from: usize) -> Option<String> {
    let bytes = expr.as_bytes();
    let mut index = from;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if bytes.get(index) != Some(&b'\'') {
        return None;
    }
    // Reference targets are checked only when the first argument is a literal.
    // ARM templates embed WDL in single-quoted ARM strings, so the first WDL
    // argument can arrive with each WDL quote doubled by ARM escaping.
    if bytes.get(index + 1) == Some(&b'\'')
        && let Some(arg) = first_arm_escaped_string_arg(expr, index + 2)
    {
        return Some(arg);
    }
    index += 1;
    let mut out = String::new();
    let mut segment_start = index;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' if bytes.get(index + 1) == Some(&b'\'') => {
                out.push_str(&expr[segment_start..index]);
                out.push('\'');
                index += 2;
                segment_start = index;
            }
            b'\'' => {
                out.push_str(&expr[segment_start..index]);
                return Some(out);
            }
            _ => {
                index += 1;
            }
        }
    }
    None
}

fn first_arm_escaped_string_arg(expr: &str, from: usize) -> Option<String> {
    // Dedicated path for WDL embedded inside ARM single-quoted strings, where
    // WDL quotes are doubled by ARM before the WDL scanner sees them.
    let bytes = expr.as_bytes();
    let mut index = from;
    while index + 1 < bytes.len() {
        if bytes[index] == b'\'' && bytes[index + 1] == b'\'' {
            if index == from {
                return None;
            }
            return Some(expr[from..index].to_owned());
        }
        index += 1;
    }
    None
}

/// WDL identifiers are ASCII; the first byte must be a letter or `_`.
pub(super) fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

/// Continuation bytes for a WDL identifier: letters, digits, and `_`.
pub(super) fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
