//! Top-level lint pipeline.
//!
//! Given a file or directory, this module:
//!  1. discovers workflow definitions (`workflow.json`) plus any ARM
//!     deployment template that embeds them,
//!  2. reads and parses each file,
//!  3. dispatches to the three rule families — `shape` (schema/shape),
//!     `references` (WDL reference resolution) and `project` (Standard
//!     project / repository manifest rules),
//!  4. sorts and dedups the resulting diagnostics.
//!
//! Only `Severity::Error` gates CI, so nearly every rule emits via
//! `Diagnostic::error`; non-error severities are reserved for future use.

use crate::diagnostic::Diagnostic;
use crate::json::{JsonFile, JsonReadError, span};
use crate::path_utils::{normalize_path, symlink_target_outside_root};
use std::ffi::OsStr;
use std::path::Component;
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

mod project;
mod references;
mod shape;

use project::{
    ProjectFiles, arm_resource_diagnostics, has_logic_workflow_resource,
    is_arm_deployment_template, known_parameters_for, lint_project_references, project_root,
    template_repository_manifest_diagnostics, workflow_definitions,
};
use references::{ArmReferenceContext, reference_diagnostics};
use shape::shape_diagnostics;

#[derive(Debug, Error)]
/// Errors that prevent the linter from completing.
pub enum LintError {
    /// JSON file could not be read.
    #[error(transparent)]
    Json(#[from] JsonReadError),
    /// Recursive directory walking failed.
    #[error("failed to walk {path}: {source}")]
    Walk {
        /// Input path being walked.
        path: PathBuf,
        /// Walkdir error.
        source: walkdir::Error,
    },
}

impl LintError {
    /// Path most closely associated with the fatal error.
    pub fn path(&self) -> &Path {
        match self {
            Self::Json(
                JsonReadError::Io { path, .. }
                | JsonReadError::Parse { path, .. }
                | JsonReadError::InvalidUtf8 { path, .. },
            ) => path,
            Self::Walk { path, .. } => path,
        }
    }

    /// Error message safe for machine output; it avoids embedding absolute paths.
    pub fn stable_message(&self) -> String {
        match self {
            Self::Json(JsonReadError::Io { source, .. }) => {
                format!("failed to read JSON input: {source}")
            }
            Self::Json(JsonReadError::Parse { source, .. }) => {
                format!("failed to parse JSON input: {source}")
            }
            Self::Json(JsonReadError::InvalidUtf8 { source, .. }) => {
                format!("failed to parse JSON input: {source}")
            }
            Self::Walk { source, .. } => source
                .io_error()
                .map(|error| format!("failed to walk input path: {error}"))
                .unwrap_or_else(|| "failed to walk input path".to_owned()),
        }
    }
}

/// Lint one workflow file, ARM template file, or directory tree.
pub fn lint_path(path: impl AsRef<Path>) -> Result<Vec<Diagnostic>, LintError> {
    let path = path.as_ref();
    let project_root = project_root(path);
    let workflow_paths = discover_workflows(path)?;
    let mut diagnostics = Vec::new();

    if path.is_dir() {
        let repository_manifest_path = path.join("manifest.json");
        if repository_manifest_path.is_file()
            && path_resolves_under_root(&repository_manifest_path, path)
        {
            match JsonFile::read(&repository_manifest_path) {
                Ok(manifest) => {
                    diagnostics.extend(template_repository_manifest_diagnostics(&manifest));
                }
                Err(JsonReadError::Parse { path, source }) => {
                    diagnostics.push(Diagnostic::error(
                        "json-parse-error",
                        path,
                        "",
                        None,
                        format!("failed to parse JSON: {source}"),
                    ));
                }
                Err(JsonReadError::InvalidUtf8 { path, source }) => {
                    diagnostics.push(Diagnostic::error(
                        "json-parse-error",
                        path,
                        "",
                        None,
                        format!("failed to parse JSON: {source}"),
                    ));
                }
                Err(JsonReadError::Io { path, source }) => {
                    return Err(JsonReadError::Io { path, source }.into());
                }
            }
        }
    }

    // A clean run with no inspected workflows is dangerous in CI: it usually
    // means the caller passed the wrong directory or generated tree.
    if workflow_paths.is_empty() {
        diagnostics.push(Diagnostic::error(
            "no-workflows-found",
            path,
            "",
            None,
            "no workflow.json files found under input path".to_owned(),
        ));
        return Ok(diagnostics);
    }

    for workflow_path in workflow_paths {
        let file = match JsonFile::read(&workflow_path) {
            Ok(file) => file,
            Err(JsonReadError::Parse { path, source }) => {
                diagnostics.push(Diagnostic::error(
                    "json-parse-error",
                    path,
                    "",
                    None,
                    format!("failed to parse JSON: {source}"),
                ));
                continue;
            }
            Err(JsonReadError::InvalidUtf8 { path, source }) => {
                diagnostics.push(Diagnostic::error(
                    "json-parse-error",
                    path,
                    "",
                    None,
                    format!("failed to parse JSON: {source}"),
                ));
                continue;
            }
            Err(JsonReadError::Io { path, source }) => {
                return Err(JsonReadError::Io { path, source }.into());
            }
        };
        let (project, project_diagnostics) = ProjectFiles::read(path, &project_root, &file)?;
        diagnostics.extend(project_diagnostics);
        diagnostics.extend(lint_workflow_file(&file, &project));
        // Project files are linted after workflow extraction so Standard-only
        // checks do not fire for standalone WDL or ARM deployment templates.
        diagnostics.extend(lint_project_references(&file, &project));
    }

    // `message` is part of the sort key because some diagnostics intentionally
    // share a path/pointer/code and only differ by the missing symbol name.
    diagnostics.sort_by(|a, b| {
        (&a.path, &a.pointer, &a.code, &a.message).cmp(&(&b.path, &b.pointer, &b.code, &b.message))
    });
    // Two rules can legitimately fire at the same (path, pointer, code) tuple
    // — e.g. multiple missing-reference names at one site. `diagnostic_dedup_detail`
    // opts those codes into keeping `message` as part of the identity so we
    // do not collapse independent findings into one, while still folding away
    // truly duplicate diagnostics for other codes.
    diagnostics.dedup_by(|a, b| {
        a.path == b.path
            && a.pointer == b.pointer
            && a.code == b.code
            && diagnostic_dedup_detail(a) == diagnostic_dedup_detail(b)
    });
    Ok(diagnostics)
}

/// Returns extra dedup-key material for codes that intentionally emit multiple
/// diagnostics per (path, pointer, code) tuple. `None` means "collapse duplicates
/// on the base key alone".
fn diagnostic_dedup_detail(diagnostic: &Diagnostic) -> Option<&str> {
    match diagnostic.code.as_str() {
        "project-missing-definition-parameter"
        | "project-missing-connection-parameter"
        | "project-connection-invalid-expression"
        | "project-parameter-invalid-expression"
        | "action-reference-not-runafter"
        | "item-out-of-scope"
        | "wdl-invalid-context"
        | "wdl-syntax-error"
        | "unknown-action-reference"
        | "unknown-foreach-reference"
        | "unknown-scoped-action-reference"
        | "unknown-until-reference"
        | "unknown-variable-reference"
        | "variable-reference-not-initialized"
        | "workflow-shape-invalid-context" => Some(&diagnostic.message),
        "workflow-shape-invalid-value" if diagnostic.pointer.ends_with("/operationOptions") => {
            Some(&diagnostic.message)
        }
        _ => None,
    }
}

/// Enumerate every `workflow.json` under `path`.
///
/// Filters version-control, build-output, and other generated-artifact
/// directories (see `is_ignored_dir_name`), plus any symlinked subtree that
/// escapes the input root, so that a plain directory run is deterministic
/// even when the tree contains packaged fixtures or vendored copies.
fn discover_workflows(path: &Path) -> Result<Vec<PathBuf>, LintError> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    let mut workflows = Vec::new();
    // `follow_links(true)` is intentional — Standard project layouts often
    // symlink shared workflow directories — but a symlink pointing outside the
    // root would leak diagnostics for unrelated code, so we swallow the walk
    // errors that occur when we refuse to descend such a link.
    let mut skipped_external_symlink_error = false;
    for entry in WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_entry(|entry| !is_ignored_walk_dir(entry, path))
    {
        let entry = match entry {
            Ok(entry) => {
                skipped_external_symlink_error = false;
                entry
            }
            Err(source) if source.loop_ancestor().is_some() => continue,
            Err(source) if external_symlink_path_error(&source, path) => {
                skipped_external_symlink_error = true;
                continue;
            }
            Err(source) if skipped_external_symlink_error && source.path().is_none() => {
                skipped_external_symlink_error = false;
                continue;
            }
            // A permission denial reached through an external symlink target
            // is skipped just like the canonicalize-based classifier above:
            // on Linux, the unreadable target cannot be canonicalized, so the
            // canonical classifier misses it and we fall back on the errno
            // combined with (a) our own symlink-boundary check or (b) the
            // `skipped_external_symlink_error` flag left by the previous arm
            // — walkdir may split a single external-symlink boundary across
            // several follow-up errors and only the first carries a path we
            // can classify. An in-root `chmod 000` directory matches neither
            // signal and still surfaces as a walk error.
            Err(source)
                if source
                    .io_error()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
                    && (skipped_external_symlink_error
                        || permission_denial_reached_via_symlink(&source, path)) =>
            {
                skipped_external_symlink_error = true;
                continue;
            }
            Err(source) => {
                return Err(LintError::Walk {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        if entry.file_name() == "workflow.json"
            && entry.path().is_file()
            && path_resolves_under_root(entry.path(), path)
        {
            workflows.push(entry.path().to_path_buf());
        }
    }
    workflows.sort();
    Ok(workflows)
}

/// True when a permission-denied walk error's path is reachable only through an
/// external symlink. Used as a Linux fallback for
/// [`external_symlink_path_error`], which cannot classify unreadable targets
/// because `Path::canonicalize` fails on them.
///
/// Three independent signals qualify as "reached via an external symlink":
///
/// 1. the error path canonicalizes to a location outside the walk root —
///    walkdir followed a symlink whose target lives elsewhere;
/// 2. the error path is itself a symlink whose chain cannot be canonicalized
///    (its ultimate target is unenterable), so we cannot prove it stays under
///    root and treat the permission denial as an external boundary;
/// 3. some component *inside* the walked tree is a symlink pointing outside
///    the root, so descending it produced the permission denial.
///
/// An in-root `chmod 000` directory canonicalizes cleanly (its parent is
/// readable) and is not a symlink, so it matches none of these signals and
/// still surfaces as a real walk error.
fn permission_denial_reached_via_symlink(source: &walkdir::Error, root: &Path) -> bool {
    let Some(path) = source.path() else {
        return false;
    };
    let Ok(canonical_root) = root.canonicalize() else {
        return false;
    };
    match path.canonicalize() {
        Ok(canonical_path) => {
            if !canonical_path.starts_with(&canonical_root) {
                return true;
            }
        }
        Err(_) => {
            if path.is_symlink() {
                return true;
            }
        }
    }
    path_has_external_symlink(path, &canonical_root)
}

fn external_symlink_path_error(source: &walkdir::Error, root: &Path) -> bool {
    let Some(path) = source.path() else {
        return false;
    };
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    if path_outside_root(path, &root) {
        return true;
    }
    path_has_external_symlink(path, &root)
}

fn path_outside_root(path: &Path, canonical_root: &Path) -> bool {
    let path = absolute_path(path);
    if let Ok(path) = path.canonicalize() {
        return !path.starts_with(canonical_root);
    }
    !normalize_path(path).starts_with(canonical_root)
}

fn path_has_external_symlink(path: &Path, canonical_root: &Path) -> bool {
    // Only symlinks *below* the walk root count as escapes — a `/var` symlink
    // that the operating system uses to redirect the temp hierarchy sits above
    // the walk root and would produce a spurious "external" verdict on macOS.
    // Canonicalize the walked path so its tail lines up with the canonical
    // root; when canonicalization fails (unreadable target on Linux), fall
    // back to the raw path so the classifier still runs.
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let Ok(tail) = canonical_path.strip_prefix(canonical_root) else {
        return false;
    };
    let mut current = canonical_root.to_path_buf();
    for component in tail.components() {
        current.push(component.as_os_str());
        if current.is_symlink() && symlink_target_outside_root(canonical_root, &current) {
            return true;
        }
    }
    false
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|current_dir| current_dir.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn is_ignored_walk_dir(entry: &walkdir::DirEntry, root: &Path) -> bool {
    if entry.path() == root {
        return false;
    }
    if !entry.file_type().is_dir() {
        return false;
    }
    if is_ignored_dir_name(entry.file_name()) {
        return true;
    }
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    let Ok(path) = entry.path().canonicalize() else {
        return false;
    };
    match path.strip_prefix(&root) {
        Ok(relative) => path_has_ignored_dir_component(relative),
        Err(_) => true,
    }
}

fn path_resolves_under_root(path: &Path, root: &Path) -> bool {
    let Ok(root) = root.canonicalize() else {
        return true;
    };
    let Ok(path) = path.canonicalize() else {
        return true;
    };
    if !path.starts_with(&root) {
        return false;
    }
    path.strip_prefix(&root)
        .map(|relative| !path_has_ignored_dir_component(relative))
        .unwrap_or(true)
}

fn path_has_ignored_dir_component(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(name) => is_ignored_dir_name(name),
        _ => false,
    })
}

fn is_ignored_dir_name(name: &OsStr) -> bool {
    matches!(name.to_str(), Some(".git" | ".uchgs" | "target"))
}

fn lint_workflow_file(file: &JsonFile, project: &ProjectFiles) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let is_arm_template = is_arm_deployment_template(&file.value);
    if is_arm_template {
        diagnostics.extend(arm_resource_diagnostics(file));
    }
    let candidates = workflow_definitions(file);

    if candidates.is_empty() {
        if is_arm_template && (!diagnostics.is_empty() || has_logic_workflow_resource(&file.value))
        {
            return diagnostics;
        }
        diagnostics.push(Diagnostic::error(
            "workflow-definition-not-found",
            &file.path,
            "",
            Some(span(&file.value)),
            "JSON file does not contain a Logic Apps workflow definition".to_owned(),
        ));
        return diagnostics;
    }

    for candidate in candidates {
        let definition = candidate.effective_value();
        let reference_definition = candidate.reference_value();
        if let Some(diagnostic) = candidate.kind_invalid_type_diagnostic(file) {
            diagnostics.push(diagnostic);
        }
        let workflow = if is_arm_template {
            crate::workflow::extract_definition_with_arm_scope(
                definition,
                &candidate.pointer,
                candidate.effective_kind(),
                candidate.arm_scope(),
            )
        } else {
            crate::workflow::extract_definition(
                definition,
                &candidate.pointer,
                candidate.effective_kind(),
            )
        };
        let known_parameters = known_parameters_for(file, project, &candidate.pointer);
        let definition_parameter_defaults_required =
            project.definition_parameter_defaults_required();

        diagnostics.extend(shape_diagnostics(
            file,
            definition,
            &candidate.pointer,
            &workflow,
            candidate.arm_scope(),
            &known_parameters,
            definition_parameter_defaults_required,
        ));
        diagnostics.extend(reference_diagnostics(
            file,
            reference_definition,
            &candidate.pointer,
            &workflow,
            &known_parameters,
            project.parameter_source_unreadable(),
            ArmReferenceContext {
                is_deployment_template: is_arm_template,
                scope: candidate.arm_scope(),
            },
        ));
    }

    diagnostics
}
