//! Function-call discovery for shape-level checks.
//!
//! Consumers here don't need reference resolution — they ask "does this
//! expression call `X`?", "what accessor chain follows the call?", or "list
//! every call in the expression so we can compare against an allow-list".
//! Everything is stringly-typed on purpose: rules match against WDL
//! identifiers, not AST nodes.

use super::FunctionCall;
use super::arity::argument_count;
use super::lex::{
    consume_balanced, first_string_arg, next_call, root_expression_identifier_with_end,
};
use super::segments::{
    find_interpolation_end, find_next_interpolation_start, visit_expression_segments,
};

/// Return every function call (and bare root identifier) discovered in
/// `text`, walking both root expressions and every `@{...}` interpolation.
///
/// A root form like `@parameters('x')` is scanned as an expression body
/// starting immediately after the `@`; interpolated forms are scanned per
/// segment. `@@` and `@@{...}` sequences are treated as literal `@`.
pub fn function_calls_in_string(text: &str) -> Vec<FunctionCall> {
    let mut calls = Vec::new();
    let bytes = text.as_bytes();

    if bytes.first() == Some(&b'@') && !bytes.starts_with(b"@@") && !bytes.starts_with(b"@{") {
        extract_function_calls(&text[1..], &mut calls);
        // Project JSON policy also cares about bare root identifiers such as
        // `@appsetting`, which are not parenthesized function calls.
        if let Some(name) = bare_root_expression_identifier(&text[1..]) {
            calls.push(FunctionCall {
                name: name.to_owned(),
                parenthesized: false,
            });
        }
        return calls;
    }

    let mut index = if bytes.starts_with(b"@@") { 2 } else { 0 };
    while let Some(at) = find_next_interpolation_start(bytes, index) {
        let Some(end) = find_interpolation_end(text, at + 2) else {
            break;
        };
        extract_function_calls(&text[at + 2..end], &mut calls);
        index = end + 1;
    }

    calls
}

/// Return whether a WDL string contains a zero-argument call to `function_name`.
///
/// This helper lets context checks identify `action()` even when the broader
/// call scanner has not built an AST for its accessor chain.
pub fn zero_arg_function_call_in_string(text: &str, function_name: &str) -> bool {
    let bytes = text.as_bytes();

    if bytes.first() == Some(&b'@') && !bytes.starts_with(b"@@") && !bytes.starts_with(b"@{") {
        return expr_has_zero_arg_function_call(&text[1..], function_name);
    }

    let mut index = if bytes.starts_with(b"@@") { 2 } else { 0 };
    while let Some(at) = find_next_interpolation_start(bytes, index) {
        let Some(end) = find_interpolation_end(text, at + 2) else {
            break;
        };
        if expr_has_zero_arg_function_call(&text[at + 2..end], function_name) {
            return true;
        }
        index = end + 1;
    }

    false
}

/// Return suffixes after zero-argument function calls in WDL expression segments.
pub fn zero_arg_function_call_suffixes_in_string(text: &str, function_name: &str) -> Vec<String> {
    let mut suffixes = Vec::new();
    visit_expression_segments(text, |expr| {
        collect_function_call_suffixes(expr, function_name, None, true, &mut suffixes);
    });
    suffixes
}

/// Return suffixes after calls whose first argument is the given string literal.
pub fn string_arg_function_call_suffixes_in_string(
    text: &str,
    function_name: &str,
    first_arg: &str,
) -> Vec<String> {
    let mut suffixes = Vec::new();
    visit_expression_segments(text, |expr| {
        collect_function_call_suffixes(expr, function_name, Some(first_arg), false, &mut suffixes);
    });
    suffixes
}

/// Return suffixes after all calls to `function_name` in WDL expression segments.
pub fn function_call_suffixes_in_string(text: &str, function_name: &str) -> Vec<String> {
    let mut suffixes = Vec::new();
    visit_expression_segments(text, |expr| {
        collect_any_function_call_suffixes(expr, function_name, &mut suffixes);
    });
    suffixes
}

/// Walk `expr` collecting every parenthesized call. String literals are
/// skipped by `next_call`, so `'outputs(''Fake'')'` is not reported.
fn extract_function_calls(expr: &str, calls: &mut Vec<FunctionCall>) {
    let mut index = 0;
    while index < expr.len() {
        let Some((name, args_start)) = next_call(expr, index) else {
            break;
        };
        calls.push(FunctionCall {
            name: name.to_owned(),
            parenthesized: true,
        });
        index = args_start + 1;
    }
}

fn collect_any_function_call_suffixes(expr: &str, function_name: &str, suffixes: &mut Vec<String>) {
    let mut index = 0;
    while index < expr.len() {
        let Some((name, args_start)) = next_call(expr, index) else {
            break;
        };
        // WDL function names are matched case-insensitively: authors mix
        // `triggerBody` and `triggerbody` in practice, and the runtime does
        // not care about the spelling.
        if name.eq_ignore_ascii_case(function_name)
            && let Some(end) = consume_balanced(expr, args_start, b'(', b')')
        {
            suffixes.push(expr[end..].to_owned());
            index = end;
            continue;
        }
        index = args_start + 1;
    }
}

fn collect_function_call_suffixes(
    expr: &str,
    function_name: &str,
    first_arg: Option<&str>,
    zero_args: bool,
    suffixes: &mut Vec<String>,
) {
    let mut index = 0;
    while index < expr.len() {
        let Some((name, args_start)) = next_call(expr, index) else {
            break;
        };
        if name.eq_ignore_ascii_case(function_name)
            && call_arguments_match(expr, args_start, first_arg, zero_args)
            && let Some(end) = consume_balanced(expr, args_start, b'(', b')')
        {
            suffixes.push(expr[end..].to_owned());
            index = end;
            continue;
        }
        index = args_start + 1;
    }
}

fn call_arguments_match(
    expr: &str,
    args_start: usize,
    first_arg: Option<&str>,
    zero_args: bool,
) -> bool {
    if zero_args {
        return matches!(argument_count(expr, args_start), Ok(0));
    }
    first_arg.is_some_and(|expected| {
        first_string_arg(expr, args_start + 1).is_some_and(|actual| actual == expected)
    })
}

fn expr_has_zero_arg_function_call(expr: &str, function_name: &str) -> bool {
    let mut index = 0;
    while index < expr.len() {
        let Some((name, args_start)) = next_call(expr, index) else {
            break;
        };
        if name.eq_ignore_ascii_case(function_name)
            && matches!(argument_count(expr, args_start), Ok(0))
        {
            return true;
        }
        index = args_start + 1;
    }
    false
}

/// Return the identifier at the start of a root expression only when it is
/// not followed by an argument list. `@variables` is a legal shorthand that
/// project-level policy rules need to see; `@variables(...)` is a normal
/// call and is already covered by `extract_function_calls`.
fn bare_root_expression_identifier(expr: &str) -> Option<&str> {
    let (name, mut index) = root_expression_identifier_with_end(expr)?;
    let bytes = expr.as_bytes();
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    (bytes.get(index) != Some(&b'(')).then_some(name)
}
