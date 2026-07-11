//! Diagnostic data model and the stable `--format json` contract.
//!
//! [`Diagnostic`] is the linter's internal representation; [`JsonDiagnostic`]
//! is what `--format json` emits. The JSON shape (field names, kebab-case
//! severity, path formatting, JSON Pointer semantics) is a public contract —
//! downstream tooling and CI gates depend on it — so fields must not be
//! renamed, reordered semantically, or dropped without a deliberate breaking
//! change. Additions require care too: any new field becomes load-bearing the
//! moment a consumer starts reading it.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
/// Diagnostic severity.
pub enum Severity {
    /// The issue should fail CI and produce exit code 1.
    Error,
    /// The issue is informational and does not currently fail CI.
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// A linter diagnostic with a stable JSON Pointer location.
pub struct Diagnostic {
    /// Stable rule code, such as `unknown-action-reference`.
    pub code: String,
    /// Severity used for exit-code decisions.
    pub severity: Severity,
    /// Filesystem path associated with the diagnostic.
    pub path: PathBuf,
    /// JSON Pointer to the offending value, relative to `path`.
    pub pointer: String,
    /// Optional byte span in the source file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<ByteSpan>,
    /// Human-readable diagnostic message.
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
/// Byte range within a source file.
pub struct ByteSpan {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

impl Diagnostic {
    /// Construct an error diagnostic.
    pub fn error(
        code: impl Into<String>,
        path: impl Into<PathBuf>,
        pointer: impl Into<String>,
        span: Option<ByteSpan>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Error,
            path: path.into(),
            pointer: pointer.into(),
            span,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
/// JSON-serializable diagnostic contract.
pub struct JsonDiagnostic<'a> {
    /// Stable rule code.
    pub code: &'a str,
    /// Diagnostic severity.
    pub severity: Severity,
    /// Path formatted relative to the CLI input base.
    pub path: String,
    /// JSON Pointer to the offending value.
    pub pointer: &'a str,
    /// Human-readable diagnostic message.
    pub message: &'a str,
}

impl Diagnostic {
    /// Convert this diagnostic to the stable `--format json` contract.
    pub fn as_json_contract(&self, base: &Path) -> JsonDiagnostic<'_> {
        JsonDiagnostic {
            code: &self.code,
            severity: self.severity,
            path: display_path(base, &self.path),
            pointer: &self.pointer,
            message: &self.message,
        }
    }
}

/// Escape ASCII / Unicode control characters for safe terminal display.
///
/// [`display_path`] preserves raw filename bytes so that JSON output stays
/// round-trippable, and serde escapes any control characters when it emits
/// the JSON string. Human output does not go through serde: an untrusted
/// path name that contains ANSI/OSC escapes would otherwise reach the
/// terminal verbatim and let the caller inject color changes or terminal
/// commands. This helper renders every control code as `\xNN` so a
/// malicious workflow directory name cannot rewrite the surrounding
/// diagnostic output.
pub fn sanitize_for_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_control() && c != '\t' {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Format `path` relative to `base` without normalizing filename characters.
///
/// Only path *components* are rewritten (prefix stripping, `..` synthesis for
/// sibling bases); individual filename bytes are passed through untouched so
/// byte spans computed against the original source stay valid and callers can
/// round-trip the printed path back to the file on disk. Human-output callers
/// must run the result through [`sanitize_for_terminal`] before printing.
pub fn display_path(base: &Path, path: &Path) -> String {
    let display = path
        .strip_prefix(base)
        .map(Path::to_path_buf)
        .ok()
        .or_else(|| relative_path_from_base(base, path))
        .unwrap_or_else(|| {
            path.file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| path.to_path_buf())
        });
    if display.as_os_str().is_empty() {
        return path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned();
    }
    display.to_string_lossy().into_owned()
}

fn relative_path_from_base(base: &Path, path: &Path) -> Option<PathBuf> {
    if !base.is_absolute() || !path.is_absolute() {
        return None;
    }
    let base_components = base.components().collect::<Vec<_>>();
    let path_components = path.components().collect::<Vec<_>>();
    let mut common = 0;
    while common < base_components.len()
        && common < path_components.len()
        && base_components[common] == path_components[common]
    {
        common += 1;
    }
    if common == 0 {
        return None;
    }

    let mut relative = PathBuf::new();
    for component in &base_components[common..] {
        match component {
            std::path::Component::Normal(_) => relative.push(".."),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => return None,
        }
    }
    for component in &path_components[common..] {
        match component {
            std::path::Component::Normal(part) => relative.push(part),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => relative.push(".."),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return None,
        }
    }
    (!relative.as_os_str().is_empty()).then_some(relative)
}
