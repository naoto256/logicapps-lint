//! Project-scope WDL-expression checks.
//!
//! `parameters.json` and `connections.json` values may themselves contain
//! `@parameters('x')` / `@appsetting('y')` — a tiny sub-language distinct
//! from ARM template expressions. Each caller supplies the file label and
//! the whitelist of expression functions its file is permitted to use.
use crate::diagnostic::Diagnostic;
use crate::json::JsonFile;
use crate::wdl::{FunctionCall, function_calls_in_string, syntax_issues_in_string};
use crate::workflow::string_sites;

pub(super) fn project_json_expression_diagnostics(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    code: &str,
    file_label: &str,
    allowed_functions: &[&str],
) -> Vec<Diagnostic> {
    string_sites(value, pointer)
        .into_iter()
        .flat_map(|site| {
            let mut diagnostics = Vec::new();
            for issue in syntax_issues_in_string(site.value.as_ref()) {
                diagnostics.push(Diagnostic::error(
                    "wdl-syntax-error",
                    &file.path,
                    site.pointer.clone(),
                    Some(site.span),
                    issue.message,
                ));
            }
            diagnostics.extend(invalid_project_expression_calls(
                file,
                &site,
                code,
                file_label,
                allowed_functions,
            ));
            diagnostics
        })
        .collect()
}

/// Diagnostics for a single string site: reject ARM `[...]` full-expressions
/// (project files use `@...` WDL syntax) and any WDL function calls outside
/// `allowed_functions`.
pub(super) fn invalid_project_expression_calls(
    file: &JsonFile,
    site: &crate::workflow::StringSite<'_>,
    code: &str,
    file_label: &str,
    allowed_functions: &[&str],
) -> Vec<Diagnostic> {
    if crate::arm::is_full_expression(site.value.as_ref()) {
        return vec![Diagnostic::error(
            code,
            &file.path,
            site.pointer.clone(),
            Some(site.span),
            format!(
                "{file_label} does not support ARM template expressions; use {}",
                allowed_functions
                    .iter()
                    .map(|name| format!("@{name}"))
                    .collect::<Vec<_>>()
                    .join(" or ")
            ),
        )];
    }
    function_calls_in_string(site.value.as_ref())
        .into_iter()
        .filter(|call| {
            !call.parenthesized || !project_expression_function_allowed(call, allowed_functions)
        })
        .map(|call| {
            Diagnostic::error(
                code,
                &file.path,
                site.pointer.clone(),
                Some(site.span),
                format!(
                    "{file_label} only allows {} expression functions; found '{}'",
                    allowed_functions
                        .iter()
                        .map(|name| format!("@{name}"))
                        .collect::<Vec<_>>()
                        .join(" or "),
                    call.name
                ),
            )
        })
        .collect()
}

fn project_expression_function_allowed(call: &FunctionCall, allowed_functions: &[&str]) -> bool {
    allowed_functions
        .iter()
        .any(|allowed| call.name.eq_ignore_ascii_case(allowed))
}
