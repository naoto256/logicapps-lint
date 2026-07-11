//! Segmentation of WDL-bearing JSON strings into expression bodies.
//!
//! WDL values arrive in two shapes: a "root" expression that begins with a
//! single `@`, or plain text containing zero or more `@{...}` interpolations.
//! This module hands each expression body (without its outer `@`/`@{...}`)
//! to a visitor so the other scanners can share a single traversal
//! implementation and stay consistent about escape handling.

/// Call `visit` once per expression body inside `text`, transparently
/// unwrapping the root-`@` or `@{...}` shell. `@@` and `@@{...}` are skipped
/// as literal `@` and do not produce a visited segment.
pub(super) fn visit_expression_segments(text: &str, mut visit: impl FnMut(&str)) {
    let bytes = text.as_bytes();

    if bytes.first() == Some(&b'@') && !bytes.starts_with(b"@@") && !bytes.starts_with(b"@{") {
        visit(&text[1..]);
        return;
    }

    let mut index = if bytes.starts_with(b"@@") { 2 } else { 0 };
    while let Some(at) = find_next_interpolation_start(bytes, index) {
        let Some(end) = find_interpolation_end(text, at + 2) else {
            break;
        };
        visit(&text[at + 2..end]);
        index = end + 1;
    }
}

/// Locate the byte index of the next `@{` interpolation opener at or after
/// `from`, skipping over `@@{...}` escape sequences.
pub(super) fn find_next_interpolation_start(bytes: &[u8], from: usize) -> Option<usize> {
    let mut index = from;
    while index + 1 < bytes.len() {
        // `@@{...}` is a literal `@{...}`, but later `@{...}` segments in the
        // same string still need to be discovered.
        if bytes[index] == b'@'
            && bytes[index + 1] == b'{'
            && index.checked_sub(1).and_then(|prev| bytes.get(prev)) != Some(&b'@')
        {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// Return the index of the `}` that closes the interpolation whose body
/// begins at `from`. Braces inside single-quoted string literals are
/// ignored so `@{concat('}')}` closes at the outer brace, not the one
/// embedded in the literal. Returns `None` when the interpolation is
/// unterminated — callers surface that as a syntax issue.
pub(super) fn find_interpolation_end(text: &str, from: usize) -> Option<usize> {
    let mut quote = false;
    let mut depth = 1usize;
    let bytes = text.as_bytes();
    let mut index = from;

    while index < bytes.len() {
        match bytes[index] {
            b'\'' => {
                // WDL escapes single quotes by doubling them. Escaped quotes do
                // not toggle string mode, so braces inside the literal stay literal.
                if quote && bytes.get(index + 1) == Some(&b'\'') {
                    index += 2;
                    continue;
                }
                quote = !quote;
            }
            b'{' if !quote => depth += 1,
            b'}' if !quote => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index += 1;
    }

    None
}
