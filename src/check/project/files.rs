//! Project discovery and file loading.
//!
//! Walks up from the workflow file to find a project root, classifies the
//! project shape (Standard / Template / neither), and reads the auxiliary
//! files the rule modules need. Every "nearest ancestor" search stops at the
//! detected root so we do not accidentally pull siblings from outside the
//! project. Read failures are split into two kinds:
//!
//! - parse / UTF-8 problems become diagnostics on the auxiliary file and
//!   the caller degrades to "cannot know";
//! - I/O errors abort the whole read, because a rule that reports "missing
//!   parameter" while parameters.json is unreadable would mislead the user.
use super::arm::is_arm_deployment_template;
use super::parameters::collect_project_parameter_names;
use super::template::{
    collect_template_manifest_metadata, template_manifest_container_diagnostics,
    template_manifest_is_consumption_only, template_manifest_relationship_diagnostics,
    template_manifest_shape_diagnostics, template_package_manifest_has_package_evidence,
    template_package_manifest_shape_diagnostics, template_workflow_wrapper_diagnostics,
};
use super::types::ConnectionReferenceKind;
use crate::diagnostic::Diagnostic;
use crate::json::{JsonFile, JsonReadError, get};
use crate::path_utils;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Everything the project-scope rules need about the file's neighbours.
///
/// Populated once per lint invocation; the rule modules read it but do not
/// mutate it. The `*_unreadable` flags are the "cannot know" signal — rules
/// consult them before promoting absence into a diagnostic.
#[derive(Debug)]
pub(in crate::check) struct ProjectFiles {
    /// True when a Standard project root was detected (host.json marker or
    /// Standard-shaped `workflow.json` with a project sibling).
    pub(super) standard_project: bool,
    /// Nearest `parameters.json` / `workflowparameters.json` peers.
    pub(super) parameters: Vec<JsonFile>,
    /// Nearest `connections.json`, if any.
    pub(super) connections: Option<JsonFile>,
    parameter_names: BTreeSet<String>,
    template_parameters: BTreeSet<String>,
    /// Connection names published by the template manifest, tagged with the
    /// connection kinds they can satisfy.
    pub(super) template_connections: BTreeMap<String, BTreeSet<ConnectionReferenceKind>>,
    /// True when the file sits under a template package (manifest.json present).
    pub(super) template_workflow: bool,
    /// True when the template is *not* consumption-only (so Standard-shape
    /// checks such as `$connections` handling apply).
    pub(super) template_standard_capable: bool,
    /// Parameter source existed but could not be parsed / read cleanly.
    pub(super) parameter_source_unreadable: bool,
    /// Connection source (connections.json or manifests) was similarly unreadable.
    pub(super) connection_source_unreadable: bool,
}

impl ProjectFiles {
    /// Load the auxiliary files around `file` under `root`.
    ///
    /// `input` is the path the caller was originally asked to lint (a file or
    /// directory); it's used to guard against inheriting a parent template
    /// manifest that lies outside the requested scope.
    pub(in crate::check) fn read(
        input: &Path,
        root: &Path,
        file: &JsonFile,
    ) -> Result<(Self, Vec<Diagnostic>), JsonReadError> {
        let mut diagnostics = Vec::new();
        let input_root = input.to_path_buf();
        let project_root = project_root_marker(&file.path);
        let standard_project = is_standard_project_workflow(file) && project_root.is_some();
        let template_project = project_root
            .as_ref()
            .is_some_and(|root| candidate_exists_under_root(root, &root.join("manifest.json")));
        if standard_project
            && project_root
                .as_ref()
                .is_some_and(|root| file.path.parent() != Some(root.as_path()))
        {
            validate_standard_workflow_name(file, &mut diagnostics);
        }
        // Without a Standard marker, direct `workflow.json` input stays in
        // standalone mode even if the caller's base has unrelated project files.
        let local_root = if let Some(project_root) = project_root {
            project_root
        } else {
            root.to_path_buf()
        };
        let root = local_root.as_path();
        let (parameters, parameters_unreadable) = if standard_project {
            find_nearest_json_files_any(
                root,
                &file.path,
                &["parameters.json", "workflowparameters.json"],
                true,
                &mut diagnostics,
            )?
        } else {
            (Vec::new(), false)
        };
        let (connections, connections_unreadable) = if standard_project {
            find_nearest_json_with_presence(root, &file.path, "connections.json", &mut diagnostics)?
        } else {
            (None, false)
        };
        let (manifests, manifests_unreadable) = if standard_project || template_project {
            find_nearest_manifest_files(root, &file.path, &mut diagnostics)?
        } else {
            (Vec::new(), false)
        };
        let (parent_template_manifest, parent_manifest_unreadable) =
            if (standard_project || template_project) && manifests.len() == 1 {
                find_parent_template_manifest(&input_root, root, &manifests[0], &mut diagnostics)?
            } else {
                (None, false)
            };
        if let Some(parent_manifest) = &parent_template_manifest
            && (file
                .path
                .parent()
                .and_then(|parent| parent.file_name())
                .is_some_and(|name| name == "default")
                || template_package_manifest_has_package_evidence(&parent_manifest.value)
                || (get(&parent_manifest.value, "parameters").is_none()
                    && get(&parent_manifest.value, "connections").is_none()))
        {
            diagnostics.extend(template_package_manifest_shape_diagnostics(parent_manifest));
        }
        let parameter_names = parameters
            .iter()
            .flat_map(|file| collect_project_parameter_names(&file.value))
            .collect();
        let mut template_parameters = BTreeSet::new();
        let mut template_connections = BTreeMap::new();
        let mut template_workflow = false;
        let mut template_standard_capable = false;

        // A manifest sitting next to the workflow file is a per-workflow
        // template manifest; farther away it is a package or repository
        // container manifest and gets a different rule set.
        for manifest in &manifests {
            if manifest.path.parent() == file.path.parent() {
                diagnostics.extend(template_manifest_shape_diagnostics(manifest));
                if let Some(parent_manifest) = &parent_template_manifest {
                    diagnostics.extend(template_manifest_relationship_diagnostics(
                        parent_manifest,
                        manifest,
                    ));
                }
                template_workflow = true;
                template_standard_capable |= parent_template_manifest
                    .as_ref()
                    .is_some_and(|parent| !template_manifest_is_consumption_only(&parent.value))
                    || (parent_template_manifest.is_none()
                        && !template_manifest_is_consumption_only(&manifest.value));
                diagnostics.extend(template_workflow_wrapper_diagnostics(file));
            } else if template_package_manifest_has_package_evidence(&manifest.value) {
                diagnostics.extend(template_package_manifest_shape_diagnostics(manifest));
            } else {
                diagnostics.extend(template_manifest_container_diagnostics(manifest));
            }
            collect_template_manifest_metadata(
                &manifest.value,
                &mut template_parameters,
                &mut template_connections,
            );
        }

        Ok((
            Self {
                standard_project,
                parameters,
                connections,
                parameter_names,
                template_parameters,
                template_connections,
                template_workflow,
                template_standard_capable,
                parameter_source_unreadable: parameters_unreadable,
                connection_source_unreadable: connections_unreadable
                    || manifests_unreadable
                    || parent_manifest_unreadable,
            },
            diagnostics,
        ))
    }

    /// Union of parameter names supplied by either the parameters files or the
    /// template manifest — a workflow parameter reference is satisfied if
    /// either source names it.
    pub(super) fn known_parameter_names(&self) -> BTreeSet<String> {
        let mut names = self.parameter_names.clone();
        names.extend(self.template_parameters.iter().cloned());
        names
    }

    /// Standalone workflows must self-supply parameter defaults; Standard and
    /// Template projects can lean on the sibling files instead.
    pub(in crate::check) fn definition_parameter_defaults_required(&self) -> bool {
        !self.standard_project && !self.template_workflow
    }

    pub(in crate::check) fn parameter_source_unreadable(&self) -> bool {
        self.parameter_source_unreadable
    }
}

fn is_standard_project_workflow(file: &JsonFile) -> bool {
    // A file named `workflow.json` can still be an ARM deployment template in
    // tests or migration repos; only real Standard workflow files use project files.
    file.path
        .file_name()
        .is_some_and(|name| name == "workflow.json")
        && !is_arm_deployment_template(&file.value)
        && get(&file.value, "definition").is_some()
}

fn validate_standard_workflow_name(file: &JsonFile, diagnostics: &mut Vec<Diagnostic>) {
    let Some(name) = file
        .path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
    else {
        return;
    };
    if name.chars().count() <= 32 {
        return;
    }
    diagnostics.push(Diagnostic::error(
        "workflow-shape-invalid-value",
        &file.path,
        "",
        None,
        format!("Standard workflow name '{name}' exceeds the 32 character limit"),
    ));
}

fn find_nearest_json_with_presence(
    root: &Path,
    workflow_path: &Path,
    file_name: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(Option<JsonFile>, bool), JsonReadError> {
    let Some(parent) = workflow_path.parent() else {
        return Ok((None, false));
    };
    for ancestor in parent.ancestors() {
        let candidate = ancestor.join(file_name);
        if candidate_exists_under_root(root, &candidate) {
            let file = read_optional_json(candidate, diagnostics)?;
            let unreadable = file.is_none();
            return Ok((file, unreadable));
        }
        if ancestor == root {
            break;
        }
    }
    Ok((None, false))
}

fn find_nearest_json_files_any(
    root: &Path,
    workflow_path: &Path,
    file_names: &[&str],
    skip_arm_deployment_parameters: bool,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(Vec<JsonFile>, bool), JsonReadError> {
    let Some(parent) = workflow_path.parent() else {
        return Ok((Vec::new(), false));
    };
    for ancestor in parent.ancestors() {
        let mut found = false;
        let mut unreadable = false;
        let mut files = Vec::new();
        for file_name in file_names {
            let candidate = ancestor.join(file_name);
            if candidate_exists_under_root(root, &candidate) {
                if skip_arm_deployment_parameters
                    && *file_name == "parameters.json"
                    && standard_project_arm_deployment_parameters_file(&candidate)
                {
                    // Standard apps and ARM deployments both use `parameters.json`.
                    // A workflowparameters.json peer should still be discovered, but
                    // ARM deployment parameters must not be linted as Standard values.
                    continue;
                }
                found = true;
                if let Some(file) = read_optional_json(candidate, diagnostics)? {
                    files.push(file);
                } else {
                    unreadable = true;
                }
            }
        }
        if found {
            // `parameters.json` and `workflowparameters.json` are peers. Once a
            // nearer directory declares either, parent directories must not fill gaps.
            return Ok((files, unreadable));
        }
        if ancestor == root {
            break;
        }
    }
    Ok((Vec::new(), false))
}

fn find_nearest_manifest_files(
    root: &Path,
    workflow_path: &Path,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(Vec<JsonFile>, bool), JsonReadError> {
    let Some(parent) = workflow_path.parent() else {
        return Ok((Vec::new(), false));
    };

    for ancestor in parent.ancestors() {
        let candidate = ancestor.join("manifest.json");
        if candidate_exists_under_root(root, &candidate) {
            // Template manifests are package boundaries. The nearest manifest
            // wins so parent packages cannot satisfy child workflow references.
            if let Some(manifest) = read_optional_json(candidate, diagnostics)? {
                return Ok((vec![manifest], false));
            }
            return Ok((Vec::new(), true));
        }
        if ancestor == root {
            break;
        }
    }

    Ok((Vec::new(), false))
}

// Symlinks that escape the root are treated as absent so that a project cannot
// smuggle in sibling files from outside the tree under lint.
fn candidate_exists_under_root(root: &Path, candidate: &Path) -> bool {
    // Canonicalize once so the symlink target check and the fallback membership
    // test below share the resolved root instead of re-walking it.
    if candidate.is_symlink()
        && let Ok(canonical_root) = root.canonicalize()
        && path_utils::symlink_target_outside_root(&canonical_root, candidate)
    {
        return false;
    }
    let Ok(metadata) = fs::metadata(candidate) else {
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

fn find_parent_template_manifest(
    input_root: &Path,
    root: &Path,
    local_manifest: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(Option<JsonFile>, bool), JsonReadError> {
    let Some(workflow_dir) = local_manifest.path.parent() else {
        return Ok((None, false));
    };
    let Some(template_dir) = workflow_dir.parent() else {
        return Ok((None, false));
    };
    if !input_root.is_file() && input_root != workflow_dir && !template_dir.starts_with(input_root)
    {
        return Ok((None, false));
    }
    if candidate_exists_under_root(root, &root.join("host.json")) && !template_dir.starts_with(root)
    {
        return Ok((None, false));
    }
    let candidate = template_dir.join("manifest.json");
    if candidate == local_manifest.path || !candidate_exists_under_root(template_dir, &candidate) {
        return Ok((None, false));
    }
    let file = read_optional_json(candidate, diagnostics)?;
    let unreadable = file.is_none();
    Ok((file, unreadable))
}

fn read_optional_json(
    path: PathBuf,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Option<JsonFile>, JsonReadError> {
    match JsonFile::read(&path) {
        Ok(file) => Ok(Some(file)),
        Err(JsonReadError::Parse { path, source }) => {
            // Parse errors are diagnostics attached to the auxiliary file. I/O
            // errors abort because derived missing-reference findings would be misleading.
            diagnostics.push(Diagnostic::error(
                "json-parse-error",
                path,
                "",
                None,
                format!("failed to parse JSON: {source}"),
            ));
            Ok(None)
        }
        Err(JsonReadError::InvalidUtf8 { path, source }) => {
            diagnostics.push(Diagnostic::error(
                "json-parse-error",
                path,
                "",
                None,
                format!("failed to parse JSON: {source}"),
            ));
            Ok(None)
        }
        Err(error @ JsonReadError::Io { .. }) => Err(error),
    }
}

/// Best-effort project root for `path`.
///
/// Falls back to the file's directory (or `.` for bare files) when no
/// project marker is present — the caller then lints in standalone mode.
pub(in crate::check) fn project_root(path: &Path) -> PathBuf {
    project_root_marker(path).unwrap_or_else(|| {
        if path.is_dir() {
            path.to_path_buf()
        } else {
            path.parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        }
    })
}

fn project_root_marker(path: &Path) -> Option<PathBuf> {
    let start = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or_else(|| Path::new("."))
    };

    for ancestor in start.ancestors() {
        // `manifest.json` and `host.json` are hard package/project boundaries.
        // Prefer the nearest boundary over looser parameter/connection markers.
        if candidate_exists_under_root(ancestor, &ancestor.join("manifest.json")) {
            return Some(ancestor.to_path_buf());
        }
        if candidate_exists_under_root(ancestor, &ancestor.join("host.json")) {
            return Some(ancestor.to_path_buf());
        }
    }

    for ancestor in start.ancestors() {
        if candidate_exists_under_root(ancestor, &ancestor.join("workflowparameters.json"))
            || candidate_exists_under_root(ancestor, &ancestor.join("connections.json"))
            || (candidate_exists_under_root(ancestor, &ancestor.join("parameters.json"))
                && standard_parameters_marker(&ancestor.join("parameters.json")))
        {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

fn standard_parameters_marker(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    // parameters.json is shared by Standard projects and ARM deployment inputs.
    // Only the former should turn a standalone workflow into project-mode lint.
    !is_arm_deployment_parameters_file(path)
}

fn is_arm_deployment_parameters_file(path: &Path) -> bool {
    declared_arm_deployment_parameters_file(path) || schema_less_deployment_parameters_file(path)
}

fn standard_project_arm_deployment_parameters_file(path: &Path) -> bool {
    declared_arm_deployment_parameters_file(path)
        || schema_less_deployment_parameters_with_content_version_file(path)
}

fn declared_arm_deployment_parameters_file(path: &Path) -> bool {
    let Ok(source) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&source) else {
        return false;
    };
    value
        .get("$schema")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|schema| schema.contains("/deploymentParameters.json"))
}

fn schema_less_deployment_parameters_file(path: &Path) -> bool {
    let Ok(source) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&source) else {
        return false;
    };
    schema_less_deployment_parameters(&value)
}

fn schema_less_deployment_parameters_with_content_version_file(path: &Path) -> bool {
    let Ok(source) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&source) else {
        return false;
    };
    value
        .as_object()
        .is_some_and(|root| root.contains_key("contentVersion"))
        && schema_less_deployment_parameters(&value)
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
        // Empty `parameters` is too weak by itself; Standard project files can
        // be empty while authored. ARM deployment files normally carry contentVersion.
        return root.contains_key("contentVersion");
    }
    parameters.values().all(|parameter| {
        parameter.as_object().is_some_and(|object| {
            (object.contains_key("value") || object.contains_key("reference"))
                && !object.contains_key("type")
        })
    })
}
