//! Lightweight lexer/parser primitives for ARM expression syntax.
//!
//! Handles the surface grammar without evaluating anything: recognising the
//! outer `[...]` wrapper, splitting a call into `name(arg, arg, ...)` plus a
//! trailing accessor chain, tokenising single-quoted string literals, and
//! walking balanced brackets. The evaluator in `eval.rs` layers semantics on
//! top of these primitives.
//!
//! ARM string escape rules honoured here:
//! - `[[...]` at the very start is the escape for a literal `[...]` and is
//!   *not* an expression.
//! - Inside single-quoted string literals, `''` escapes a single quote.

/// True when `text` is exactly one `[expression]`, with a syntactically valid
/// head call. Rejects the literal-bracket escape `[[...]` up front.
pub(crate) fn is_full_expression(text: &str) -> bool {
    let trimmed = text.trim();
    let Some(inner) = trimmed
        .strip_prefix('[')
        .and_then(|text| text.strip_suffix(']'))
    else {
        return false;
    };
    // `[[literal]` is ARM's own escape for a literal leading `[` — it means
    // the runtime should treat the value as the string `[literal]`, not as an
    // expression to evaluate.
    if trimmed.starts_with("[[") {
        return false;
    }
    let inner = inner.trim();
    if inner.is_empty() {
        return false;
    }
    arm_expression_head_call_is_valid(inner)
}

/// Return true when the expression contains an `@` outside of any
/// single-quoted string literal.
///
/// Used to detect Logic Apps WDL escapes that leaked into ARM expression
/// context (typically a diagnostic-worthy mistake): an `@` inside a
/// `'literal'` is fine and stays part of the string.
pub(crate) fn full_expression_contains_unquoted_wdl(text: &str) -> bool {
    let Some(inner) = full_expression_inner(text) else {
        return false;
    };
    let bytes = inner.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\'' {
            let Some(end) = skip_arm_string_literal(bytes, index) else {
                return false;
            };
            index = end;
            continue;
        }
        if bytes[index] == b'@' {
            return true;
        }
        index += 1;
    }
    false
}

/// Strip the outer `[...]` from a full expression and return the trimmed
/// interior. Returns `None` if `text` is not a valid full expression.
pub(super) fn full_expression_inner(text: &str) -> Option<&str> {
    if !is_full_expression(text) {
        return None;
    }
    text.trim()
        .strip_prefix('[')?
        .strip_suffix(']')
        .map(str::trim)
}

/// Parse `<digits>]` at the start of `text` (i.e. the tail of a `[N]` accessor
/// whose leading `[` the caller already consumed). Returns the index and the
/// remainder past the closing `]`.
pub(super) fn arm_array_index_accessor(text: &str) -> Option<(usize, &str)> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if index == 0 {
        return None;
    }
    let array_index = text[..index].parse().ok()?;
    let rest = text[index..].trim_start();
    Some((array_index, rest.strip_prefix(']')?))
}

/// Parse an identifier that follows a `.` accessor. Allows alphanumerics,
/// underscore, and hyphen (some Logic Apps property names contain `-`).
pub(super) fn arm_dot_accessor(text: &str) -> Option<(&str, &str)> {
    let bytes = text.as_bytes();
    let mut end = 0usize;
    while end < bytes.len()
        && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'-'))
    {
        end += 1;
    }
    (end > 0).then_some((&text[..end], &text[end..]))
}

/// Result of splitting a call-shaped expression into its parts. `args` are raw
/// slices — outer whitespace not trimmed — because the caller may want to
/// re-parse them (e.g. as another call) preserving spans.
pub(super) struct ArmFunctionCall<'a> {
    pub(super) name: &'a str,
    pub(super) args: Vec<&'a str>,
    /// Everything after the closing `)`. Typically a chain of `.foo` /
    /// `['bar']` / `[0]` accessors, or empty.
    pub(super) tail: &'a str,
}

/// Split `expr` into `name(args...)tail`. Respects nested brackets and skips
/// over single-quoted ARM string literals (which may contain unbalanced
/// bracket characters).
pub(super) fn arm_function_call(expr: &str) -> Option<ArmFunctionCall<'_>> {
    let expr = expr.trim();
    let open = expr.find('(')?;
    let name = expr[..open].trim();
    if name.is_empty() {
        return None;
    }
    let bytes = expr.as_bytes();
    let mut args = Vec::new();
    let mut depth = 1usize;
    let mut start = open + 1;
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' => {
                let (_, end) = arm_string_literal(expr, index)?;
                index = end;
                continue;
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    args.push(&expr[start..index]);
                    return Some(ArmFunctionCall {
                        name,
                        args,
                        tail: &expr[index + 1..],
                    });
                }
            }
            b']' | b'}' => {
                depth = depth.checked_sub(1)?;
            }
            b',' if depth == 1 => {
                args.push(&expr[start..index]);
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// Convenience over [`arm_function_call`] that returns the argument list only
/// when `expr` is exactly a call to `function_name` with no trailing accessors.
pub(super) fn arm_function_args<'a>(expr: &'a str, function_name: &str) -> Option<Vec<&'a str>> {
    let call = arm_function_call(expr)?;
    if !call.name.eq_ignore_ascii_case(function_name) || !call.tail.trim().is_empty() {
        return None;
    }
    Some(call.args)
}

/// Parse an ARM single-quoted string literal starting at byte offset `start`.
/// Handles `''` as an escaped single quote (ARM's own escape rule; there is no
/// backslash escaping). Returns the decoded value and the index just past the
/// closing quote.
pub(super) fn arm_string_literal(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'\'') {
        return None;
    }
    let mut index = start + 1;
    let mut segment_start = index;
    let mut value = String::new();
    while index < bytes.len() {
        if bytes[index] == b'\'' {
            // `''` is only treated as an escape when there is a later closing
            // quote — otherwise it's an empty literal `''` immediately
            // followed by another literal, and we must terminate here.
            if bytes.get(index + 1) == Some(&b'\'') && has_later_quote(bytes, index + 2) {
                value.push_str(&text[segment_start..index]);
                value.push('\'');
                index += 2;
                segment_start = index;
                continue;
            }
            value.push_str(&text[segment_start..index]);
            return Some((value, index + 1));
        }
        index += 1;
    }
    None
}

fn has_later_quote(bytes: &[u8], from: usize) -> bool {
    bytes.get(from..).is_some_and(|tail| tail.contains(&b'\''))
}

// Structural validation of `name(args)tail` without evaluating anything.
// Additionally enforces the arity rule that `parameters`/`variables` take
// exactly one argument — a cheap way to reject obviously-malformed
// expressions before the evaluator sees them.
fn arm_expression_head_call_is_valid(expr: &str) -> bool {
    let bytes = expr.as_bytes();
    let mut index = 0;
    if !bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_alphabetic())
    {
        return false;
    }
    index += 1;
    while index < bytes.len()
        && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'.'))
    {
        index += 1;
    }
    let name = &expr[..index];
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if bytes.get(index) != Some(&b'(') {
        return false;
    }
    let Ok((argument_count, end)) = arm_argument_count(expr, index) else {
        return false;
    };
    if matches!(
        name.to_ascii_lowercase().as_str(),
        "parameters" | "variables"
    ) && argument_count != 1
    {
        return false;
    }
    arm_expression_tail_is_accessor(&expr[end..])
}

// Accept a possibly-empty sequence of accessors (`.ident` or `[...]`) after a
// call. Anything else at the top level makes the whole thing not a full
// expression.
fn arm_expression_tail_is_accessor(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index == bytes.len() {
            return true;
        }
        match bytes[index] {
            b'.' => {
                index += 1;
                if !bytes
                    .get(index)
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_'))
                {
                    return false;
                }
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_'))
                {
                    index += 1;
                }
            }
            b'[' => {
                let Some(next) = consume_arm_balanced(text, index, b'[', b']') else {
                    return false;
                };
                index = next;
            }
            _ => return false,
        }
    }
    true
}

// Count top-level arguments of a call whose opening `(` sits at `open_index`.
// Returns the count plus the index just past the matching `)`. Tracks a
// bracket stack so nested `(`, `[`, `{` are properly matched, and skips over
// string literals whose contents may look like unbalanced brackets.
fn arm_argument_count(expr: &str, open_index: usize) -> Result<(usize, usize), ()> {
    let bytes = expr.as_bytes();
    let mut stack = vec![b')'];
    let mut count = 0usize;
    let mut has_argument = false;
    let mut index = open_index + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' => {
                has_argument = true;
                index = skip_arm_string_literal(bytes, index).ok_or(())?;
                continue;
            }
            b'(' => {
                if stack.len() == 1 {
                    has_argument = true;
                }
                stack.push(b')');
            }
            b'[' => {
                if stack.len() == 1 {
                    has_argument = true;
                }
                stack.push(b']');
            }
            b'{' => {
                if stack.len() == 1 {
                    has_argument = true;
                }
                stack.push(b'}');
            }
            b')' | b']' | b'}' => {
                let Some(expected) = stack.pop() else {
                    return Err(());
                };
                if bytes[index] != expected {
                    return Err(());
                }
                if stack.is_empty() {
                    return Ok((count + usize::from(has_argument), index + 1));
                }
            }
            b',' if stack.len() == 1 => {
                if !has_argument {
                    return Err(());
                }
                count += 1;
                has_argument = false;
            }
            byte if !byte.is_ascii_whitespace() && stack.len() == 1 => {
                has_argument = true;
            }
            _ => {}
        }
        index += 1;
    }
    Err(())
}

// Walk past a balanced `open` … `close` span, respecting single-quoted
// ARM string literals so their contents cannot unbalance the count.
fn consume_arm_balanced(text: &str, open_index: usize, open: u8, close: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open_index) != Some(&open) {
        return None;
    }
    let mut depth = 1usize;
    let mut index = open_index + 1;
    while index < bytes.len() {
        if bytes[index] == b'\'' {
            index = skip_arm_string_literal(bytes, index)?;
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

// Skip an ARM string literal without decoding it. `''` inside is always the
// escape here — this helper runs in contexts (bracket counting, WDL scan)
// where we already know we're inside a well-formed expression, so the
// "no later closing quote" ambiguity handled by `arm_string_literal` doesn't
// apply.
fn skip_arm_string_literal(bytes: &[u8], from: usize) -> Option<usize> {
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
