//! CLI entry point for `logicapps-lint`.
//!
//! Parses arguments with clap, runs [`lint_path`] over the requested target,
//! applies `--allow` / `--warn` severity overrides, and prints diagnostics in
//! either the human or JSON format. The process exits `1` iff any surviving
//! diagnostic is still an [`Severity::Error`]; `2` is reserved for tool errors
//! (argv mistakes, unreadable inputs, serialization failures).

use clap::{Parser, ValueEnum, error::ErrorKind};
use logicapps_lint::path_utils;
use logicapps_lint::{
    Diagnostic, LintError, Severity, display_path, lint_path, relax_diagnostics,
    sanitize_for_terminal,
};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod human;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Local linter for Azure Logic Apps workflow definitions"
)]
struct Cli {
    #[arg(default_value = ".")]
    path: PathBuf,

    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    /// Downgrade the given diagnostic code to warning severity (repeatable).
    #[arg(long = "warn", value_name = "CODE")]
    warn: Vec<String>,

    /// Suppress the given diagnostic code entirely (repeatable).
    #[arg(long = "allow", value_name = "CODE")]
    allow: Vec<String>,

    /// Enforce the documented schema literally. By default, the linter accepts
    /// case variants that Azure Logic Apps' runtime accepts (for example
    /// `SUCCEEDED` as a `runAfter` status, or `string` as a parameter type),
    /// and downgrades registry-gap diagnostics to warnings. `--strict` reports
    /// all of these as errors.
    #[arg(long)]
    strict: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                return ExitCode::SUCCESS;
            }
            // clap has already failed parsing, so we cannot trust `cli.format`.
            // Peek at argv directly so JSON callers still receive JSON on argv
            // errors instead of an unparseable human-formatted usage string.
            if args_request_json_format() {
                return print_json_usage_error(&error);
            }
            let _ = error.print();
            return ExitCode::from(2);
        }
    };
    let target = cli.path.clone();
    let output_base = if target.is_file() {
        project_output_base(&target).unwrap_or_else(|| {
            target
                .parent()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
        })
    } else {
        project_output_base(&target).unwrap_or_else(|| target.clone())
    };

    let diagnostics = match lint_path(&target) {
        Ok(diagnostics) => {
            let diagnostics = relax_diagnostics(diagnostics, cli.strict);
            apply_severity_overrides(diagnostics, &cli.allow, &cli.warn)
        }
        Err(error) => {
            if matches!(cli.format, OutputFormat::Json) {
                return print_json_error(&output_base, &target, &error);
            }
            let path = tool_error_path(&output_base, &target, &error);
            eprintln!(
                "logicapps-lint: {}: {}",
                sanitize_for_terminal(&display_path(&output_base, &path)),
                error.stable_message()
            );
            return ExitCode::from(2);
        }
    };

    match cli.format {
        OutputFormat::Human => human::print(&output_base, &diagnostics),
        OutputFormat::Json => {
            let contract: Vec<_> = diagnostics
                .iter()
                .map(|diagnostic| diagnostic.as_json_contract(&output_base))
                .collect();
            let json = match serde_json::to_string_pretty(&contract) {
                Ok(json) => json,
                Err(error) => {
                    eprintln!("logicapps-lint: failed to serialize diagnostics: {error}");
                    return ExitCode::from(2);
                }
            };
            println!("{json}");
        }
    }

    // Exit `1` iff at least one diagnostic remains at Error severity after
    // `--allow` / `--warn` overrides. Warnings alone must not fail CI.
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Error)
    {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Apply `--allow` (suppress) and `--warn` (downgrade) overrides in that order.
///
/// `--allow` is applied first and unconditionally drops the diagnostic; a code
/// listed in both `--allow` and `--warn` is therefore suppressed, matching the
/// usual "stronger suppression takes precedence" convention.
fn apply_severity_overrides(
    diagnostics: Vec<Diagnostic>,
    allow: &[String],
    warn: &[String],
) -> Vec<Diagnostic> {
    diagnostics
        .into_iter()
        .filter(|diagnostic| !allow.iter().any(|code| code == &diagnostic.code))
        .map(|mut diagnostic| {
            if warn.iter().any(|code| code == &diagnostic.code) {
                diagnostic.severity = Severity::Warning;
            }
            diagnostic
        })
        .collect()
}

/// Best-effort argv scan for `--format json` before clap runs.
///
/// Used only when clap parsing itself has already failed: we still want JSON
/// callers to receive a JSON-shaped tool error rather than a human usage
/// string. Handles the `--format json`, `--format=json`, and `--` separator
/// forms; anything else conservatively falls back to human output.
fn args_request_json_format() -> bool {
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == OsStr::new("--") {
            return false;
        }
        if arg == OsStr::new("--format") {
            return args.next().is_some_and(|value| value == OsStr::new("json"));
        }
        if let Some(text) = arg.to_str()
            && text == "--format=json"
        {
            return true;
        }
    }
    false
}

fn print_json_usage_error(error: &clap::Error) -> ExitCode {
    let path = PathBuf::from(".");
    let diagnostic = Diagnostic::error(
        "tool-error",
        &path,
        "",
        None,
        redact_absolute_paths(&error.to_string()),
    );
    let contract = [diagnostic.as_json_contract(&path)];
    match serde_json::to_string_pretty(&contract) {
        Ok(json) => {
            println!("{json}");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("logicapps-lint: failed to serialize diagnostics: {error}");
            ExitCode::from(2)
        }
    }
}

fn redact_absolute_paths(message: &str) -> String {
    let mut redacted = String::with_capacity(message.len());
    let mut index = 0;
    while index < message.len() {
        let rest = &message[index..];
        if rest.starts_with('\'') && is_absolute_path_start(&rest[1..]) {
            redacted.push('\'');
            let search_start = index + 1;
            if let Some(close_offset) = closing_path_quote(&message[search_start..]) {
                redacted.push_str("<path>'");
                index = search_start + close_offset + 1;
            } else {
                redacted.push_str("<path>");
                index = message.len();
            }
        } else if is_absolute_path_start(rest) {
            redacted.push_str("<path>");
            index += embedded_absolute_path_len(rest);
        } else {
            let ch = rest.chars().next().expect("valid char boundary");
            redacted.push(ch);
            index += ch.len_utf8();
        }
    }
    redacted
}

fn is_absolute_path_start(text: &str) -> bool {
    if text.starts_with('/') || text.starts_with("\\\\") {
        return true;
    }
    let bytes = text.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(1) == Some(&b':')
        && bytes
            .get(2)
            .is_some_and(|byte| matches!(byte, b'/' | b'\\'))
}

fn embedded_absolute_path_len(text: &str) -> usize {
    if let Some(close_offset) = closing_path_quote(text) {
        return close_offset;
    }
    text.char_indices()
        .find_map(|(offset, ch)| {
            if ch.is_whitespace() || matches!(ch, '\'' | '"') {
                Some(offset)
            } else {
                None
            }
        })
        .unwrap_or(text.len())
}

fn closing_path_quote(text: &str) -> Option<usize> {
    text.char_indices()
        .filter_map(|(offset, ch)| {
            if ch == '\'' && path_quote_terminator(&text[offset + ch.len_utf8()..]) {
                Some(offset)
            } else {
                None
            }
        })
        .next_back()
}

fn path_quote_terminator(text: &str) -> bool {
    text.is_empty()
        || text == " found"
        || text.starts_with(" found\n\n")
        || text.starts_with(" found\r\n\r\n")
}

fn print_json_error(base: &Path, target: &Path, error: &LintError) -> ExitCode {
    let path = tool_error_path(base, target, error);
    let diagnostic = Diagnostic::error("tool-error", path, "", None, error.stable_message());
    let contract = [diagnostic.as_json_contract(base)];
    match serde_json::to_string_pretty(&contract) {
        Ok(json) => {
            println!("{json}");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("logicapps-lint: failed to serialize diagnostics: {error}");
            ExitCode::from(2)
        }
    }
}

fn tool_error_path(base: &Path, target: &Path, error: &LintError) -> PathBuf {
    if error.path().strip_prefix(base).is_ok() {
        error.path().to_path_buf()
    } else {
        target.to_path_buf()
    }
}

fn project_output_base(path: &Path) -> Option<PathBuf> {
    let start = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or_else(|| Path::new("."))
    };

    for ancestor in start.ancestors() {
        if marker_file_under_root(ancestor, &ancestor.join("manifest.json")) {
            return Some(ancestor.to_path_buf());
        }
        if marker_file_under_root(ancestor, &ancestor.join("host.json")) {
            return Some(ancestor.to_path_buf());
        }
    }

    for ancestor in start.ancestors() {
        if marker_file_under_root(ancestor, &ancestor.join("workflowparameters.json"))
            || marker_file_under_root(ancestor, &ancestor.join("connections.json"))
            || standard_parameters_marker(ancestor, &ancestor.join("parameters.json"))
        {
            return Some(ancestor.to_path_buf());
        }
    }

    None
}

fn standard_parameters_marker(root: &Path, path: &Path) -> bool {
    if !marker_file_under_root(root, path) {
        return false;
    }
    // parameters.json is shared by Standard projects and ARM deployment inputs.
    // Only the former should affect the diagnostic path base.
    !is_arm_deployment_parameters_file(path)
}

fn marker_file_under_root(root: &Path, candidate: &Path) -> bool {
    if candidate.is_symlink()
        && let Ok(canonical_root) = root.canonicalize()
        && path_utils::symlink_target_outside_root(&canonical_root, candidate)
    {
        return false;
    }
    let Ok(metadata) = std::fs::metadata(candidate) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    let Ok(root) = root.canonicalize() else {
        return true;
    };
    let Ok(candidate) = candidate.canonicalize() else {
        return true;
    };
    candidate.starts_with(root)
}

fn is_arm_deployment_parameters_file(path: &Path) -> bool {
    let Ok(source) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&source) else {
        return false;
    };
    value
        .get("$schema")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|schema| schema.contains("/deploymentParameters.json"))
        || schema_less_deployment_parameters(&value)
}

fn schema_less_deployment_parameters(value: &serde_json::Value) -> bool {
    let Some(root) = value.as_object() else {
        return false;
    };
    if !root
        .keys()
        .all(|key| matches!(key.as_str(), "$schema" | "contentVersion" | "parameters"))
    {
        return false;
    }
    let Some(parameters) = value
        .get("parameters")
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    if parameters.is_empty() {
        return root.contains_key("contentVersion");
    }
    parameters.values().all(|parameter| {
        parameter.as_object().is_some_and(|object| {
            (object.contains_key("value") || object.contains_key("reference"))
                && !object.contains_key("type")
        })
    })
}
