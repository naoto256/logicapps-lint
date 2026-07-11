//! Syntax-level checks over WDL-bearing JSON strings.
//!
//! This module is deliberately conservative: it only flags issues that a
//! human reviewer could confirm without evaluating the expression. When a
//! delimiter error is discovered, downstream arity checks are suppressed
//! so that a single missing bracket does not fan out into a cascade of
//! misleading arity messages.

use super::SyntaxIssue;
use super::arity::reference_call_syntax_issues;
use super::lex::{
    call_at_expression_start, consume_balanced, delimiters_match, is_ident_continue,
    is_ident_start, skip_string_literal,
};
use super::segments::find_interpolation_end;

/// Report syntax issues in `text` without building an AST.
///
/// The traversal mirrors the segmenting logic in `segments.rs`: root
/// expressions are inspected as a whole (including a check for illegal
/// plain-text suffixes), and each `@{...}` interpolation is inspected
/// individually. Escape sequences `@@` and `@@{...}` are honored so that
/// authors who deliberately emit a literal `@` are not warned.
pub fn syntax_issues_in_string(text: &str) -> Vec<SyntaxIssue> {
    let mut issues = Vec::new();
    let bytes = text.as_bytes();

    if bytes.first() == Some(&b'@') && !bytes.starts_with(b"@@") && !bytes.starts_with(b"@{") {
        let expr = &text[1..];
        issues.extend(syntax_issues_in_expr(expr));
        if root_expression_has_plain_text_suffix(expr) {
            issues.push(SyntaxIssue {
                message: "WDL root expression has plain text after the expression; use interpolation with @{...}".to_owned(),
            });
        }
        return issues;
    }

    let mut index = if bytes.starts_with(b"@@") { 2 } else { 0 };

    while index < bytes.len() {
        if bytes[index] != b'@' {
            index += 1;
            continue;
        }
        if bytes.get(index + 1) == Some(&b'@') {
            index += 2;
            continue;
        }
        if bytes.get(index + 1) == Some(&b'{') {
            let Some(end) = find_interpolation_end(text, index + 2) else {
                issues.push(SyntaxIssue {
                    message: "WDL interpolation is missing a closing '}'".to_owned(),
                });
                break;
            };
            issues.extend(syntax_issues_in_expr(&text[index + 2..end]));
            index = end + 1;
            continue;
        }
        if unbraced_expression_at(text, index) {
            issues.push(SyntaxIssue {
                message: "WDL expression inside plain text must use interpolation with @{...}"
                    .to_owned(),
            });
        }
        index += 1;
    }

    issues
}

/// Detect an unbraced `@identifier(...)` inside plain text.
///
/// Logic Apps only evaluates a bare `@` at position 0 of a string; anywhere
/// else the author must use interpolation. Missing the `@{...}` is a
/// common mistake — the runtime silently keeps the text literal, and the
/// action then receives a URL like `/subscriptions/@appsetting('X')`. We
/// flag it here so the author notices before deployment.
fn unbraced_expression_at(text: &str, at: usize) -> bool {
    let bytes = text.as_bytes();
    if bytes.get(at) != Some(&b'@') {
        return false;
    }
    let mut index = at + 1;
    let Some(byte) = bytes.get(index) else {
        return false;
    };
    if !is_ident_start(*byte) {
        return false;
    }
    index += 1;
    while index < bytes.len() && is_ident_continue(bytes[index]) {
        index += 1;
    }
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    bytes.get(index) == Some(&b'(')
}

/// Scan a single expression body for delimiter and string-literal issues,
/// then delegate arity checks to `reference_call_syntax_issues` — but only
/// when no delimiter error was seen, since arity counting on a garbled
/// bracket structure would produce more noise than signal.
fn syntax_issues_in_expr(expr: &str) -> Vec<SyntaxIssue> {
    let mut issues = Vec::new();
    let mut stack = Vec::new();
    let mut delimiter_error = false;
    let mut double_quote_reported = false;
    let bytes = expr.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'\'' => {
                let Some(next) = skip_string_literal(bytes, index) else {
                    issues.push(SyntaxIssue {
                        message: "WDL expression has an unclosed string literal".to_owned(),
                    });
                    return issues;
                };
                index = next;
                continue;
            }
            b'"' if !double_quote_reported => {
                double_quote_reported = true;
                issues.push(SyntaxIssue {
                    message: "WDL expression uses a double-quoted string literal".to_owned(),
                });
            }
            b'"' => {}
            b'(' | b'[' | b'{' => stack.push(bytes[index]),
            b')' | b']' | b'}' => {
                let Some(open) = stack.last().copied() else {
                    delimiter_error = true;
                    issues.push(SyntaxIssue {
                        message: "WDL expression has an unmatched closing delimiter".to_owned(),
                    });
                    index += 1;
                    continue;
                };
                if !delimiters_match(open, bytes[index]) {
                    delimiter_error = true;
                    issues.push(SyntaxIssue {
                        message: "WDL expression has mismatched delimiters".to_owned(),
                    });
                } else {
                    stack.pop();
                }
            }
            _ => {}
        }
        index += 1;
    }

    if !stack.is_empty() {
        if !delimiter_error {
            issues.push(SyntaxIssue {
                message: "WDL expression has an unclosed delimiter".to_owned(),
            });
        }
        delimiter_error = true;
    }

    if !delimiter_error {
        issues.extend(reference_call_syntax_issues(expr));
    }
    issues
}

/// Return true when a root expression is followed by text that is not a
/// valid accessor chain. Root form (`@parameters('x').body`) permits
/// dotted and bracket accessors; anything else — a slash, a space, another
/// character — indicates the author meant to write interpolation
/// (`@{parameters('x')}/suffix`) and the runtime will silently treat the
/// tail as literal text.
fn root_expression_has_plain_text_suffix(expr: &str) -> bool {
    let Some((_name, args_start)) = call_at_expression_start(expr) else {
        return false;
    };
    let Some(mut cursor) = consume_balanced(expr, args_start, b'(', b')') else {
        return false;
    };
    let bytes = expr.as_bytes();

    loop {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor == bytes.len() {
            return false;
        }
        match bytes[cursor] {
            // Root expressions may be followed by accessors. Anything else is
            // usually a missing interpolation boundary, e.g. `@parameters('x')/id`.
            b'?' if bytes.get(cursor + 1) == Some(&b'[') => {
                let Some(next) = consume_balanced(expr, cursor + 1, b'[', b']') else {
                    return false;
                };
                cursor = next;
            }
            b'?' if bytes.get(cursor + 1) == Some(&b'.') => {
                cursor += 2;
                if cursor >= bytes.len() || !is_ident_start(bytes[cursor]) {
                    return true;
                }
                cursor += 1;
                while cursor < bytes.len() && is_ident_continue(bytes[cursor]) {
                    cursor += 1;
                }
            }
            b'[' => {
                let Some(next) = consume_balanced(expr, cursor, b'[', b']') else {
                    return false;
                };
                cursor = next;
            }
            b'.' => {
                cursor += 1;
                if cursor >= bytes.len() || !is_ident_start(bytes[cursor]) {
                    return true;
                }
                cursor += 1;
                while cursor < bytes.len() && is_ident_continue(bytes[cursor]) {
                    cursor += 1;
                }
            }
            _ => return true,
        }
    }
}
