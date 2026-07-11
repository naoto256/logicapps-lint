//! Arity checks for WDL helper functions that this linter recognizes.
//!
//! The scanner does not know every Logic Apps expression function, so the
//! table in `reference_function_arity` is intentionally curated: it lists
//! only the helpers whose wrong-arity form the linter can flag with
//! confidence. Anything not in the table is silently accepted, which keeps
//! false positives out when Logic Apps ships new expression functions.

use super::SyntaxIssue;
use super::lex::{
    consume_balanced, is_ident_continue, is_ident_start, next_call, skip_string_literal,
};

/// Scan `expr` for calls to known helpers and emit arity/argument issues.
///
/// `expr` is the WDL expression body with the outer `@` or `@{...}` already
/// stripped by the caller. The walker advances past each call's identifier
/// even when we do not recognize it, so a malformed inner call cannot stop
/// checking of later top-level calls.
pub(super) fn reference_call_syntax_issues(expr: &str) -> Vec<SyntaxIssue> {
    let mut issues = Vec::new();
    let mut index = 0;
    while index < expr.len() {
        let Some((name, args_start)) = next_call(expr, index) else {
            break;
        };
        if let Some(arity) = reference_function_arity(name) {
            match argument_count(expr, args_start) {
                Ok(actual) if !arity.accepts(actual) => {
                    issues.push(SyntaxIssue {
                        message: arity.message(name, actual),
                    });
                }
                Err(ArgumentIssue::Empty) => {
                    issues.push(SyntaxIssue {
                        message: format!("WDL function '{name}' has an empty argument"),
                    });
                }
                Err(ArgumentIssue::Malformed) => {
                    issues.push(SyntaxIssue {
                        message: format!("WDL function '{name}' has malformed arguments"),
                    });
                }
                _ => {}
            }
        }
        index = args_start + 1;
    }
    issues
}

/// Arity spec for a known helper. `AtLeast` covers variadic helpers such as
/// `concat` where fewer than the minimum arguments is unambiguously wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FunctionArity {
    Exact(usize),
    AtLeast(usize),
}

impl FunctionArity {
    fn accepts(self, actual: usize) -> bool {
        match self {
            Self::Exact(expected) => actual == expected,
            Self::AtLeast(minimum) => actual >= minimum,
        }
    }

    fn message(self, name: &str, actual: usize) -> String {
        match self {
            Self::Exact(expected) => {
                format!("WDL function '{name}' expects {expected} argument(s), found {actual}")
            }
            Self::AtLeast(minimum) => {
                format!(
                    "WDL function '{name}' expects at least {minimum} argument(s), found {actual}"
                )
            }
        }
    }
}

fn reference_function_arity(name: &str) -> Option<FunctionArity> {
    // Curated table for helpers this linter gives semantic meaning to. It is
    // not a complete catalog of every Logic Apps expression function.
    match name {
        "actions" | "body" | "iterationIndexes" | "items" | "outputs" | "parameters" | "result"
        | "variables" | "appsetting" => Some(FunctionArity::Exact(1)),
        "formDataMultiValues" | "formDataValue" | "multipartBody" => Some(FunctionArity::Exact(2)),
        "action" | "item" | "listCallbackUrl" | "trigger" | "triggerBody" | "triggerOutputs"
        | "triggerbody" | "workflow" => Some(FunctionArity::Exact(0)),
        "triggerFormDataMultiValues" | "triggerFormDataValue" | "triggerMultipartBody" => {
            Some(FunctionArity::Exact(1))
        }
        "concat" => Some(FunctionArity::AtLeast(2)),
        _ => None,
    }
}

/// Reason `argument_count` refused to return a number.
///
/// `Empty` distinguishes a syntactically valid but user-error case
/// (`foo(,)`, `foo('a',,)`); `Malformed` covers everything else — mismatched
/// brackets, an unterminated string, or garbage after a closed argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ArgumentIssue {
    Empty,
    Malformed,
}

/// Count top-level arguments of the call whose `(` sits at `args_start`.
///
/// The scanner is intentionally forgiving: it tracks a delimiter stack so
/// nested calls and bracket accessors do not perturb the top-level comma
/// count, and it accepts trailing accessors (`.field`, `?['x']`) on a closed
/// argument because reference helpers are frequently invoked as
/// `outputs('A')?['body']`. Any bracket that does not match its opener
/// aborts with `Malformed` — bailing out here is what stops downstream
/// checks from asserting arity on garbled input.
pub(super) fn argument_count(expr: &str, args_start: usize) -> Result<usize, ArgumentIssue> {
    let bytes = expr.as_bytes();
    if bytes.get(args_start) != Some(&b'(') {
        return Err(ArgumentIssue::Malformed);
    }

    // Track expected closing delimiters so nested calls do not affect top-level
    // comma counting, and mismatched brackets cannot underflow the scanner.
    let mut stack = vec![b')'];
    let mut count = 0usize;
    let mut has_argument = false;
    let mut argument_closed = false;
    let mut index = args_start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' => {
                // A new string literal after the previous argument was already
                // closed by an accessor chain (`foo('a')?['b'] 'c'`) is a
                // syntax error, not a fresh argument.
                if stack.len() == 1 && argument_closed {
                    return Err(ArgumentIssue::Malformed);
                }
                has_argument = true;
                index = skip_string_literal(bytes, index).ok_or(ArgumentIssue::Malformed)?;
                if stack.len() == 1 {
                    argument_closed = true;
                }
                continue;
            }
            b'(' => {
                if stack.len() == 1 && argument_closed {
                    return Err(ArgumentIssue::Malformed);
                }
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
                    return Err(ArgumentIssue::Malformed);
                };
                if bytes[index] != expected {
                    return Err(ArgumentIssue::Malformed);
                }
                if stack.is_empty() {
                    if !has_argument && count > 0 {
                        return Err(ArgumentIssue::Empty);
                    }
                    return Ok(count + usize::from(has_argument));
                }
                if stack.len() == 1 {
                    argument_closed = true;
                }
            }
            b',' if stack.len() == 1 => {
                if !has_argument {
                    return Err(ArgumentIssue::Empty);
                }
                count += 1;
                has_argument = false;
                argument_closed = false;
            }
            byte if !byte.is_ascii_whitespace() && stack.len() == 1 => {
                if argument_closed {
                    if let Some(next) = skip_accessor(expr, index) {
                        index = next;
                        continue;
                    }
                    return Err(ArgumentIssue::Malformed);
                }
                has_argument = true;
            }
            _ => {}
        }
        index += 1;
    }
    Err(ArgumentIssue::Malformed)
}

/// Consume a single accessor suffix (`.field`, `?['x']`, `?.field`, `[…]`)
/// that trails a closed argument, returning the byte index one past the
/// accessor or `None` if the shape is not an accessor at all.
fn skip_accessor(expr: &str, index: usize) -> Option<usize> {
    let bytes = expr.as_bytes();
    match bytes[index] {
        b'.' => {
            let mut cursor = index + 1;
            if !bytes.get(cursor).copied().is_some_and(is_ident_start) {
                return None;
            }
            cursor += 1;
            while cursor < bytes.len() && is_ident_continue(bytes[cursor]) {
                cursor += 1;
            }
            Some(cursor)
        }
        b'?' if bytes.get(index + 1) == Some(&b'[') => {
            consume_balanced(expr, index + 1, b'[', b']')
        }
        b'?' if bytes.get(index + 1) == Some(&b'.') => {
            let mut cursor = index + 2;
            if !bytes.get(cursor).copied().is_some_and(is_ident_start) {
                return None;
            }
            cursor += 1;
            while cursor < bytes.len() && is_ident_continue(bytes[cursor]) {
                cursor += 1;
            }
            Some(cursor)
        }
        b'[' => consume_balanced(expr, index, b'[', b']'),
        _ => None,
    }
}
