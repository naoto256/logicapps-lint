//! Library entry points for `logicapps-lint`.
//!
//! The crate is primarily a CLI, but exposes a small API for running the same
//! linter over a path and consuming the resulting diagnostics.

#![warn(missing_docs)]

mod arm;
mod check;
mod diagnostic;
mod json;
mod strictness;
mod wdl;
mod workflow;

/// Filesystem path helpers shared by the linter and its CLI.
pub mod path_utils;

/// Run the linter and return diagnostics for an input path.
pub use check::{LintError, lint_path};
/// Diagnostic data structures and JSON output helpers.
pub use diagnostic::{
    ByteSpan, Diagnostic, JsonDiagnostic, Severity, display_path, sanitize_for_terminal,
};
/// Apply the strict/lenient policy that gates runtime-tolerated case variants
/// and registry-gap diagnostics. See the function's own docs for the table.
pub use strictness::relax_diagnostics;
