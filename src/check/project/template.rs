//! LogicAppsTemplates repository / package / workflow manifest validation.
//!
//! Templates are shipped as a three-level hierarchy:
//!
//! - a repository manifest listing package folder names;
//! - a **package manifest** (`manifest.json` at the package root) declaring
//!   id / title / skus / workflows / featuredConnectors / details / tags;
//! - one **workflow manifest** per workflow subdirectory, describing that
//!   workflow's parameters, connections, kinds, and images.
//!
//! The shape is authored by the LogicAppsTemplates team and evolves; the
//! validators below encode the current expectations and the relationships
//! between the levels (e.g. workflow manifest fields that must match the
//! parent package when only one workflow exists, connector metadata that
//! must actually appear on a registered workflow, name suffix conventions).
//!
//! Rule additions land here as the upstream spec changes. Field-level checks
//! are repetitive by design; the non-obvious cross-level rules carry
//! inline comments explaining the invariant.
use super::types::{ConnectionReferenceKind, ConnectionReferenceSite};
use crate::diagnostic::Diagnostic;
use crate::json::{JsonFile, as_object, as_string, get, pointer_join, span};
use crate::wdl::{
    ReferenceKind, references_in_string, string_arg_function_call_suffixes_in_string,
};
use crate::workflow::string_sites;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

const WORKFLOW_NAME_SUFFIX: &str = "_#workflowname#";
const TEMPLATE_CATEGORIES: &[&str] = &[
    "Design Patterns",
    "AI",
    "B2B",
    "EDI",
    "Approval",
    "RAG",
    "Automation",
    "BizTalk Migration",
    "Mainframe Modernization",
];

/// Extract the parameter names and connection metadata a workflow manifest
/// publishes, so cross-file checks know what the manifest advertises.
///
/// A manifest entry only "counts" as evidence when it carries enough
/// metadata to be a real declaration — see
/// `template_connection_entry_has_metadata` — so a null / half-authored
/// entry cannot mask a genuine missing reference.
pub(super) fn collect_template_manifest_metadata(
    value: &json_spanned_value::spanned::Value,
    parameters: &mut BTreeSet<String>,
    connections: &mut BTreeMap<String, BTreeSet<ConnectionReferenceKind>>,
) {
    if let Some(parameter_values) = get(value, "parameters").and_then(|value| value.as_span_array())
    {
        for parameter in parameter_values.iter() {
            if template_parameter_entry_has_metadata(parameter)
                && let Some(name) = get(parameter, "name").and_then(as_string)
            {
                parameters.insert(name.to_owned());
            }
        }
    }

    if let Some(connection_values) = get(value, "connections") {
        if let Some(object) = as_object(connection_values) {
            for (name, value) in object.iter() {
                if template_manifest_metadata_name_valid(name)
                    && template_connection_entry_has_metadata(value)
                {
                    insert_template_connection_metadata(
                        connections,
                        name,
                        ConnectionReferenceKind::Template,
                    );
                    if let Some(kind) = template_connection_reference_kind(value) {
                        insert_template_connection_metadata(connections, name, kind);
                    }
                }
            }
        } else if let Some(array) = connection_values.as_span_array() {
            for value in array.iter() {
                if template_connection_entry_has_metadata(value) {
                    for name in collect_template_connection_names(value) {
                        insert_template_connection_metadata(
                            connections,
                            &name,
                            ConnectionReferenceKind::Template,
                        );
                        if let Some(kind) = template_connection_reference_kind(value) {
                            insert_template_connection_metadata(connections, &name, kind);
                        }
                    }
                }
            }
        }
    }
}

/// True when the manifest's `skus` array is present and lists only
/// `"consumption"`. Standard-shape checks are skipped for such workflows.
pub(super) fn template_manifest_is_consumption_only(
    value: &json_spanned_value::spanned::Value,
) -> bool {
    let Some(skus) = get(value, "skus").and_then(|value| value.as_span_array()) else {
        return false;
    };
    !skus.is_empty()
        && skus
            .iter()
            .all(|sku| as_string(sku).is_some_and(|sku| sku.eq_ignore_ascii_case("consumption")))
}

/// Heuristic: distinguish a package-level manifest from a workflow-level one.
/// Package manifests carry at least one of these fields; workflow manifests
/// do not. Used to route into the right validator set.
pub(super) fn template_package_manifest_has_package_evidence(
    value: &json_spanned_value::spanned::Value,
) -> bool {
    ["skus", "workflows", "featuredConnectors", "details"]
        .iter()
        .any(|field| get(value, field).is_some())
}

/// Top-level dispatch for a per-workflow template manifest.
///
/// Fires the full checklist: required fields, markdown fields, kinds,
/// artifacts, images, parameters and connections. Individual validators
/// stay focused on a single field or invariant so the entry list here
/// doubles as an index of what shape the workflow manifest must have.
pub(super) fn template_manifest_shape_diagnostics(manifest: &JsonFile) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    validate_template_manifest_required_top_level(manifest, &mut diagnostics);
    validate_template_markdown_field(manifest, "summary", &mut diagnostics);
    validate_template_optional_markdown_field(manifest, "description", &mut diagnostics);
    validate_template_optional_markdown_field(manifest, "prerequisites", &mut diagnostics);
    validate_template_manifest_kinds(manifest, &mut diagnostics);
    validate_workflow_template_manifest_artifacts(manifest, &mut diagnostics);
    validate_template_manifest_images(manifest, &mut diagnostics);
    match get(&manifest.value, "parameters") {
        Some(parameters) => {
            if let Some(parameter_values) = parameters.as_span_array() {
                for (index, parameter) in parameter_values.iter().enumerate() {
                    validate_template_parameter_entry(
                        manifest,
                        parameter,
                        &pointer_join("/parameters", &index.to_string()),
                        &mut diagnostics,
                    );
                }
            } else {
                diagnostics.push(Diagnostic::error(
                    "template-manifest-invalid-type",
                    &manifest.path,
                    "/parameters",
                    Some(span(parameters)),
                    "template manifest parameters must be an array",
                ));
            }
        }
        None => diagnostics.push(Diagnostic::error(
            "template-manifest-missing-field",
            &manifest.path,
            "/parameters",
            Some(span(&manifest.value)),
            "template manifest is missing required field 'parameters'",
        )),
    }

    match get(&manifest.value, "connections") {
        Some(connection_values) => {
            if let Some(object) = as_object(connection_values) {
                for (name, value) in object.iter() {
                    validate_template_manifest_name(
                        manifest,
                        name,
                        &pointer_join("/connections", name),
                        Some(span(value)),
                        "connection",
                        &mut diagnostics,
                    );
                    validate_template_connection_connector_id(
                        manifest,
                        value,
                        &pointer_join(&pointer_join("/connections", name), "connectorId"),
                        &mut diagnostics,
                    );
                    validate_template_connection_kind(
                        manifest,
                        value,
                        &pointer_join(&pointer_join("/connections", name), "kind"),
                        &mut diagnostics,
                    );
                }
            } else if let Some(array) = connection_values.as_span_array() {
                for (index, value) in array.iter().enumerate() {
                    let entry_pointer = pointer_join("/connections", &index.to_string());
                    let name_pointer = pointer_join(&entry_pointer, "name");
                    if let Some(name) = get(value, "name").and_then(as_string) {
                        validate_template_manifest_name(
                            manifest,
                            name,
                            &name_pointer,
                            get(value, "name").map(span),
                            "connection",
                            &mut diagnostics,
                        );
                    }
                    validate_template_connection_connector_id(
                        manifest,
                        value,
                        &pointer_join(&entry_pointer, "connectorId"),
                        &mut diagnostics,
                    );
                    validate_template_connection_kind(
                        manifest,
                        value,
                        &pointer_join(&entry_pointer, "kind"),
                        &mut diagnostics,
                    );
                }
            } else {
                diagnostics.push(Diagnostic::error(
                    "template-manifest-invalid-type",
                    &manifest.path,
                    "/connections",
                    Some(span(connection_values)),
                    "template manifest connections must be an object or array",
                ));
            }
        }
        None => diagnostics.push(Diagnostic::error(
            "template-manifest-missing-field",
            &manifest.path,
            "/connections",
            Some(span(&manifest.value)),
            "template manifest is missing required field 'connections'",
        )),
    }
    diagnostics
}

/// Top-level dispatch for a package (multi-workflow) manifest.
///
/// Package manifests have a richer required set than workflow manifests: id,
/// title, summary, skus, workflows, featuredConnectors, details. The order
/// below intentionally interleaves shape checks (`required_top_level_field`)
/// with content checks (`validate_template_package_*`) so a bad shape does
/// not swallow every subsequent content diagnostic.
pub(super) fn template_package_manifest_shape_diagnostics(manifest: &JsonFile) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    validate_template_manifest_required_top_level_field(
        manifest,
        "id",
        "template package manifest id must be a string",
        |value| as_string(value).is_some(),
        &mut diagnostics,
    );
    validate_template_package_id(manifest, &mut diagnostics);
    validate_template_manifest_required_top_level_field(
        manifest,
        "title",
        "template package manifest title must be a string",
        |value| as_string(value).is_some(),
        &mut diagnostics,
    );
    validate_template_manifest_required_top_level_field(
        manifest,
        "summary",
        "template package manifest summary must be a string",
        |value| as_string(value).is_some(),
        &mut diagnostics,
    );
    validate_template_manifest_required_top_level_field(
        manifest,
        "skus",
        "template package manifest skus must be an array",
        |value| value.as_span_array().is_some(),
        &mut diagnostics,
    );
    validate_template_package_skus(manifest, &mut diagnostics);
    validate_template_manifest_required_top_level_field(
        manifest,
        "workflows",
        "template package manifest workflows must be an object",
        |value| as_object(value).is_some(),
        &mut diagnostics,
    );
    validate_template_package_workflows(manifest, &mut diagnostics);
    validate_template_manifest_required_top_level_field(
        manifest,
        "featuredConnectors",
        "template package manifest featuredConnectors must be an array",
        |value| value.as_span_array().is_some(),
        &mut diagnostics,
    );
    validate_template_package_featured_connectors(manifest, &mut diagnostics);
    validate_template_manifest_required_top_level_field(
        manifest,
        "details",
        "template package manifest details must be an object",
        |value| as_object(value).is_some(),
        &mut diagnostics,
    );
    validate_template_package_details_type(manifest, &mut diagnostics);
    validate_template_package_details_category(manifest, &mut diagnostics);
    validate_template_package_details_trigger(manifest, &mut diagnostics);
    validate_template_package_tags(manifest, &mut diagnostics);
    validate_template_markdown_field(manifest, "summary", &mut diagnostics);
    validate_template_optional_markdown_field(manifest, "description", &mut diagnostics);
    validate_template_package_manifest_type(manifest, &mut diagnostics);
    validate_package_template_manifest_artifacts(manifest, &mut diagnostics);
    validate_registered_template_workflow_manifests(manifest, &mut diagnostics);
    validate_template_featured_connectors_used(manifest, &mut diagnostics);
    diagnostics
}

/// Lint the repository-level manifest: an array of package folder names.
/// Each named folder must exist under the manifest directory and contain
/// its own `manifest.json` — the package layer of the hierarchy.
pub(in crate::check) fn template_repository_manifest_diagnostics(
    manifest: &JsonFile,
) -> Vec<Diagnostic> {
    let Some(packages) = manifest.value.as_span_array() else {
        return Vec::new();
    };
    let mut diagnostics = Vec::new();
    let root = manifest.path.parent().unwrap_or_else(|| Path::new(""));
    for (index, package) in packages.iter().enumerate() {
        let pointer = pointer_join("", &index.to_string());
        let Some(package_name) = as_string(package) else {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                pointer,
                Some(span(package)),
                "template repository manifest package name must be a string",
            ));
            continue;
        };
        if Path::new(package_name).file_name().and_then(OsStr::to_str) != Some(package_name) {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                pointer,
                Some(span(package)),
                "template repository manifest package name must be a local folder name",
            ));
            continue;
        }
        let package_manifest = Path::new(package_name).join("manifest.json");
        if matches!(exact_file_exists(root, &package_manifest), Some(false)) {
            diagnostics.push(Diagnostic::error(
                "template-manifest-missing-file",
                &manifest.path,
                pointer,
                Some(span(package)),
                format!(
                    "template repository package '{package_name}' does not have a package manifest"
                ),
            ));
        }
    }
    diagnostics
}

/// Cross-manifest checks between a package manifest and one of its workflow
/// manifests: the workflow id must match its folder, and when the package
/// hosts a single workflow, `title`/`summary` on the workflow must not
/// diverge from the parent (they surface as the same card to end users).
pub(super) fn template_manifest_relationship_diagnostics(
    parent_manifest: &JsonFile,
    workflow_manifest: &JsonFile,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if let Some(id) = get(&workflow_manifest.value, "id").and_then(as_string)
        && !template_package_id_matches_manifest_folder(workflow_manifest, id)
    {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &workflow_manifest.path,
            "/id",
            get(&workflow_manifest.value, "id").map(span),
            "template workflow manifest id must match the workflow folder name",
        ));
    }

    let single_workflow = get(&parent_manifest.value, "workflows")
        .and_then(as_object)
        .is_some_and(|workflows| workflows.len() == 1);
    if single_workflow {
        for field in ["title", "summary"] {
            let parent_value = get(&parent_manifest.value, field).and_then(as_string);
            let workflow_value = get(&workflow_manifest.value, field).and_then(as_string);
            if let (Some(parent_value), Some(workflow_value)) = (parent_value, workflow_value)
                && parent_value != workflow_value
            {
                diagnostics.push(Diagnostic::error(
                    "template-manifest-invalid-value",
                    &workflow_manifest.path,
                    pointer_join("", field),
                    get(&workflow_manifest.value, field).map(span),
                    format!(
                        "template workflow manifest {field} must match the parent package manifest"
                    ),
                ));
            }
        }
    }
    diagnostics
}

fn validate_template_package_id(manifest: &JsonFile, diagnostics: &mut Vec<Diagnostic>) {
    if let Some(id) = get(&manifest.value, "id").and_then(as_string)
        && !template_package_id_matches_manifest_folder(manifest, id)
    {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            "/id",
            get(&manifest.value, "id").map(span),
            "template package manifest id must match the package folder name",
        ));
    }
}

fn validate_registered_template_workflow_manifests(
    parent_manifest: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(workflows) = get(&parent_manifest.value, "workflows").and_then(as_object) else {
        return;
    };
    let Some(package_dir) = parent_manifest.path.parent() else {
        return;
    };
    for (workflow_name, workflow) in workflows {
        if !template_package_workflow_name_valid(workflow_name) {
            continue;
        }
        let workflow_manifest = package_dir
            .join(workflow_name.as_str())
            .join("manifest.json");
        if !workflow_manifest.is_file() {
            diagnostics.push(Diagnostic::error(
                "template-manifest-missing-file",
                &parent_manifest.path,
                pointer_join("/workflows", workflow_name),
                Some(span(workflow)),
                format!(
                    "template package manifest workflow '{workflow_name}' does not have a workflow manifest"
                ),
            ));
        }
    }
}

// Convention: manifest `id` mirrors the containing folder name so URLs and
// registry lookups stay stable when files are moved between packages.
fn template_package_id_matches_manifest_folder(manifest: &JsonFile, id: &str) -> bool {
    let Some(parent) = manifest.path.parent() else {
        return true;
    };
    let path_name_matches = parent
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|folder| id == folder);
    if path_name_matches {
        return true;
    }
    parent
        .canonicalize()
        .ok()
        .and_then(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .is_some_and(|folder| id == folder)
}

fn validate_template_package_skus(manifest: &JsonFile, diagnostics: &mut Vec<Diagnostic>) {
    let Some(skus) = get(&manifest.value, "skus").and_then(|value| value.as_span_array()) else {
        return;
    };
    for (index, sku) in skus.iter().enumerate() {
        let pointer = pointer_join("/skus", &index.to_string());
        let Some(text) = as_string(sku) else {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                pointer,
                Some(span(sku)),
                "template package manifest skus entries must be strings",
            ));
            continue;
        };
        if !matches!(text, "standard" | "consumption") {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                pointer,
                Some(span(sku)),
                format!("template package manifest sku '{text}' is not supported"),
            ));
        }
    }
}

fn validate_template_package_workflows(manifest: &JsonFile, diagnostics: &mut Vec<Diagnostic>) {
    let Some(workflows) = get(&manifest.value, "workflows") else {
        return;
    };
    let Some(object) = as_object(workflows) else {
        return;
    };
    if object.is_empty() {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            "/workflows",
            Some(span(workflows)),
            "template package manifest workflows must not be empty",
        ));
    }
    let single_workflow_package = object.len() == 1
        && object
            .keys()
            .all(|name| template_package_workflow_name_valid(name))
        && get(&manifest.value, "details")
            .and_then(|details| get(details, "Type"))
            .and_then(as_string)
            == Some("Workflow");
    if single_workflow_package && !object.contains_key("default") {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            "/workflows",
            Some(span(workflows)),
            "single-workflow template packages must register the 'default' workflow",
        ));
    }
    for (workflow_name, workflow) in object {
        if !template_package_workflow_name_valid(workflow_name) {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                pointer_join("/workflows", workflow_name),
                Some(span(workflows)),
                format!(
                    "template package manifest workflow name '{workflow_name}' is not supported"
                ),
            ));
        }
        let workflow_pointer = pointer_join("/workflows", workflow_name);
        if as_object(workflow).is_none() {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                workflow_pointer,
                Some(span(workflow)),
                "template package manifest workflow entry must be an object",
            ));
            continue;
        }
        let name_pointer = pointer_join(&workflow_pointer, "name");
        match get(workflow, "name") {
            Some(name) if as_string(name).is_some() => {}
            Some(name) => diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                name_pointer,
                Some(span(name)),
                "template package manifest workflow name must be a string",
            )),
            None => diagnostics.push(Diagnostic::error(
                "template-manifest-missing-field",
                &manifest.path,
                name_pointer,
                Some(span(workflow)),
                "template package manifest workflow is missing required field 'name'",
            )),
        }
    }
}

fn template_package_workflow_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
}

fn validate_template_package_details_type(manifest: &JsonFile, diagnostics: &mut Vec<Diagnostic>) {
    let Some(details) = get(&manifest.value, "details") else {
        return;
    };
    if as_object(details).is_none() {
        return;
    }
    let pointer = "/details/Type";
    let Some(details_type) = get(details, "Type") else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-missing-field",
            &manifest.path,
            pointer,
            Some(span(details)),
            "template manifest is missing required field 'Type'",
        ));
        return;
    };
    let Some(text) = as_string(details_type) else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            pointer,
            Some(span(details_type)),
            "template package manifest details.Type must be a string",
        ));
        return;
    };
    if !matches!(text, "Workflow" | "Accelerator") {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            pointer,
            Some(span(details_type)),
            format!("template package manifest details.Type '{text}' is not supported"),
        ));
    }
    validate_template_package_details_by(manifest, details, diagnostics);
}

fn validate_template_package_details_by(
    manifest: &JsonFile,
    details: &json_spanned_value::spanned::Value,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let pointer = "/details/By";
    let Some(by) = get(details, "By") else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-missing-field",
            &manifest.path,
            pointer,
            Some(span(details)),
            "template manifest is missing required field 'By'",
        ));
        return;
    };
    let Some(text) = as_string(by) else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            pointer,
            Some(span(by)),
            "template package manifest details.By must be a string",
        ));
        return;
    };
    if !text.chars().next().is_some_and(char::is_uppercase) {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            pointer,
            Some(span(by)),
            "template package manifest details.By must start with an uppercase letter",
        ));
    }
}

fn validate_template_package_details_category(
    manifest: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(details) = get(&manifest.value, "details") else {
        return;
    };
    let Some(category) = get(details, "Category") else {
        return;
    };
    let pointer = "/details/Category";
    let Some(text) = as_string(category) else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            pointer,
            Some(span(category)),
            "template package manifest details.Category must be a string",
        ));
        return;
    };
    for item in text.split(',') {
        if !TEMPLATE_CATEGORIES.contains(&item) {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                pointer,
                Some(span(category)),
                format!("template package manifest category '{item}' is not supported"),
            ));
        }
    }
}

fn validate_template_package_details_trigger(
    manifest: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(details) = get(&manifest.value, "details") else {
        return;
    };
    let Some(trigger) = get(details, "Trigger") else {
        return;
    };
    let pointer = "/details/Trigger";
    let Some(text) = as_string(trigger) else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            pointer,
            Some(span(trigger)),
            "template package manifest details.Trigger must be a string",
        ));
        return;
    };
    if !matches!(
        text,
        "Request" | "Recurrence" | "Event" | "Automated" | "Scheduled"
    ) {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            pointer,
            Some(span(trigger)),
            format!("template package manifest trigger '{text}' is not supported"),
        ));
    }
}

fn validate_template_package_tags(manifest: &JsonFile, diagnostics: &mut Vec<Diagnostic>) {
    let Some(tags) = get(&manifest.value, "tags") else {
        return;
    };
    let Some(entries) = tags.as_span_array() else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            "/tags",
            Some(span(tags)),
            "template package manifest tags must be an array",
        ));
        return;
    };
    for (index, tag) in entries.iter().enumerate() {
        let pointer = pointer_join("/tags", &index.to_string());
        let Some(text) = as_string(tag) else {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                pointer,
                Some(span(tag)),
                "template package manifest tag must be a string",
            ));
            continue;
        };
        if text.contains(',') {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                pointer,
                Some(span(tag)),
                "template package manifest tag must not contain commas",
            ));
        }
    }
}

fn validate_template_package_featured_connectors(
    manifest: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(connectors) =
        get(&manifest.value, "featuredConnectors").and_then(|value| value.as_span_array())
    else {
        return;
    };
    for (index, connector) in connectors.iter().enumerate() {
        let pointer = pointer_join("/featuredConnectors", &index.to_string());
        if as_object(connector).is_none() {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                pointer,
                Some(span(connector)),
                "template package manifest featuredConnector must be an object",
            ));
            continue;
        }
        validate_template_featured_connector_id(
            manifest,
            connector,
            &pointer_join(&pointer, "id"),
            diagnostics,
        );
        validate_template_featured_connector_kind(
            manifest,
            connector,
            &pointer_join(&pointer, "kind"),
            diagnostics,
        );
    }
}

// Cross-manifest rule: a `featuredConnectors` entry on the package must be
// referenced by at least one registered workflow's connection metadata.
// Otherwise the marketing surface (the connector card users see) would
// promote something the templates cannot actually use.
fn validate_template_featured_connectors_used(
    parent_manifest: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(connectors) =
        get(&parent_manifest.value, "featuredConnectors").and_then(|value| value.as_span_array())
    else {
        return;
    };
    for (index, connector) in connectors.iter().enumerate() {
        let pointer = pointer_join("/featuredConnectors", &index.to_string());
        let Some(kind) = get(connector, "kind").and_then(as_string) else {
            continue;
        };
        if !matches!(kind, "inapp" | "shared" | "custom" | "builtin") {
            continue;
        }
        if kind == "builtin" {
            continue;
        }
        let Some(id) = get(connector, "id").and_then(as_string) else {
            continue;
        };
        if !id.starts_with('/') && !id.starts_with("connectionProviders") {
            continue;
        }
        if !template_featured_connector_used_by_registered_workflow(parent_manifest, id, kind) {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &parent_manifest.path,
                pointer,
                Some(span(connector)),
                "template package manifest featuredConnector is not used by the workflow manifest",
            ));
        }
    }
}

fn template_featured_connector_used_by_registered_workflow(
    parent_manifest: &JsonFile,
    connector_id: &str,
    kind: &str,
) -> bool {
    // Any registered manifest we cannot read is treated as a potential match:
    // "cannot know" must not turn into a spurious `unused connector` diagnostic.
    for path in registered_template_workflow_manifest_paths(parent_manifest) {
        match JsonFile::read(&path) {
            Ok(manifest) => {
                if workflow_manifest_connection_matches(&manifest, connector_id, kind) {
                    return true;
                }
            }
            Err(_) => return true,
        }
    }
    false
}

fn registered_template_workflow_manifest_paths(parent_manifest: &JsonFile) -> Vec<PathBuf> {
    let Some(workflows) = get(&parent_manifest.value, "workflows").and_then(as_object) else {
        return Vec::new();
    };
    let Some(package_dir) = parent_manifest.path.parent() else {
        return Vec::new();
    };
    workflows
        .keys()
        .filter(|workflow_name| template_package_workflow_name_valid(workflow_name))
        .map(|workflow_name| {
            package_dir
                .join(workflow_name.as_str())
                .join("manifest.json")
        })
        .collect()
}

fn workflow_manifest_connection_matches(
    workflow_manifest: &JsonFile,
    connector_id: &str,
    kind: &str,
) -> bool {
    let Some(connections) = get(&workflow_manifest.value, "connections") else {
        return false;
    };
    if let Some(object) = as_object(connections) {
        return object
            .values()
            .any(|value| template_connection_matches(value, connector_id, kind));
    }
    connections.as_span_array().is_some_and(|values| {
        values
            .iter()
            .any(|value| template_connection_matches(value, connector_id, kind))
    })
}

fn template_connection_matches(
    value: &json_spanned_value::spanned::Value,
    connector_id: &str,
    kind: &str,
) -> bool {
    get(value, "connectorId").and_then(as_string) == Some(connector_id)
        && get(value, "kind").and_then(as_string) == Some(kind)
}

fn validate_template_featured_connector_id(
    manifest: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(id_value) = get(value, "id") else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-missing-field",
            &manifest.path,
            pointer.to_owned(),
            Some(span(value)),
            "template package manifest featuredConnector is missing required field 'id'",
        ));
        return;
    };
    let Some(id) = as_string(id_value) else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            pointer.to_owned(),
            Some(span(id_value)),
            "template package manifest featuredConnector id must be a string",
        ));
        return;
    };
    if !id.starts_with('/') && !id.starts_with("connectionProviders") {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            pointer.to_owned(),
            Some(span(id_value)),
            format!(
                "template package manifest featuredConnector id '{id}' must be an absolute path or connectionProviders id"
            ),
        ));
    }
}

fn validate_template_featured_connector_kind(
    manifest: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(kind_value) = get(value, "kind") else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-missing-field",
            &manifest.path,
            pointer.to_owned(),
            Some(span(value)),
            "template package manifest featuredConnector is missing required field 'kind'",
        ));
        return;
    };
    let Some(kind) = as_string(kind_value) else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            pointer.to_owned(),
            Some(span(kind_value)),
            "template package manifest featuredConnector kind must be a string",
        ));
        return;
    };
    if !matches!(kind, "inapp" | "shared" | "custom" | "builtin") {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            pointer.to_owned(),
            Some(span(kind_value)),
            format!("template package manifest featuredConnector kind '{kind}' is not supported"),
        ));
    }
}

fn validate_template_package_manifest_type(manifest: &JsonFile, diagnostics: &mut Vec<Diagnostic>) {
    let Some(workflows) = get(&manifest.value, "workflows").and_then(as_object) else {
        return;
    };
    let Some(details) = get(&manifest.value, "details") else {
        return;
    };
    let Some(details_type) = get(details, "Type") else {
        return;
    };
    let Some(actual) = as_string(details_type) else {
        return;
    };
    let expected = if workflows.len() > 1 {
        "Accelerator"
    } else {
        "Workflow"
    };
    if actual != expected {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            "/details/Type",
            Some(span(details_type)),
            format!("template package manifest details.Type must be '{expected}'"),
        ));
    }
}

fn validate_template_manifest_required_top_level(
    manifest: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_template_manifest_required_top_level_field(
        manifest,
        "id",
        "template manifest id must be a string",
        |value| as_string(value).is_some(),
        diagnostics,
    );
    validate_template_manifest_required_top_level_field(
        manifest,
        "title",
        "template manifest title must be a string",
        |value| as_string(value).is_some(),
        diagnostics,
    );
    validate_template_manifest_required_top_level_field(
        manifest,
        "summary",
        "template manifest summary must be a string",
        |value| as_string(value).is_some(),
        diagnostics,
    );
    validate_template_manifest_optional_top_level_field(
        manifest,
        "description",
        "template manifest description must be a string",
        |value| as_string(value).is_some(),
        diagnostics,
    );
    validate_template_manifest_required_top_level_field(
        manifest,
        "artifacts",
        "template manifest artifacts must be an array",
        |value| value.as_span_array().is_some(),
        diagnostics,
    );
    validate_template_manifest_required_top_level_field(
        manifest,
        "images",
        "template manifest images must be an object",
        |value| as_object(value).is_some(),
        diagnostics,
    );
}

fn validate_package_template_manifest_artifacts(
    manifest: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_template_manifest_artifacts(
        manifest,
        &["map", "schema", "assembly"],
        false,
        true,
        false,
        diagnostics,
    );
}

fn validate_workflow_template_manifest_artifacts(
    manifest: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_template_manifest_artifacts(manifest, &["workflow"], true, true, true, diagnostics);
}

fn validate_template_manifest_artifacts(
    manifest: &JsonFile,
    allowed_types: &[&str],
    require_workflow_artifact: bool,
    check_files: bool,
    require_local_file_name: bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(artifacts) = get(&manifest.value, "artifacts") else {
        return;
    };
    let Some(entries) = artifacts.as_span_array() else {
        return;
    };
    let base = manifest.path.parent().unwrap_or_else(|| Path::new(""));
    let mut has_workflow_artifact = false;
    for (index, artifact) in entries.iter().enumerate() {
        let pointer = pointer_join("/artifacts", &index.to_string());
        if as_object(artifact).is_none() {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                pointer,
                Some(span(artifact)),
                "template manifest artifact must be an object",
            ));
            continue;
        }

        let type_pointer = pointer_join(&pointer, "type");
        match get(artifact, "type") {
            Some(value) => match as_string(value) {
                Some("workflow") if allowed_types.contains(&"workflow") => {
                    has_workflow_artifact = true;
                }
                Some(artifact_type) if allowed_types.contains(&artifact_type) => {}
                Some(artifact_type) => diagnostics.push(Diagnostic::error(
                    "template-manifest-invalid-value",
                    &manifest.path,
                    type_pointer,
                    Some(span(value)),
                    format!("template manifest artifact type '{artifact_type}' is not supported"),
                )),
                None => diagnostics.push(Diagnostic::error(
                    "template-manifest-invalid-type",
                    &manifest.path,
                    type_pointer,
                    Some(span(value)),
                    "template manifest artifact type must be a string",
                )),
            },
            None => diagnostics.push(Diagnostic::error(
                "template-manifest-missing-field",
                &manifest.path,
                type_pointer,
                Some(span(artifact)),
                "template manifest artifact is missing required field 'type'",
            )),
        }

        let file_pointer = pointer_join(&pointer, "file");
        let Some(file_value) = get(artifact, "file") else {
            diagnostics.push(Diagnostic::error(
                "template-manifest-missing-field",
                &manifest.path,
                file_pointer,
                Some(span(artifact)),
                "template manifest artifact is missing required field 'file'",
            ));
            continue;
        };
        let Some(file_path) = as_string(file_value) else {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                file_pointer,
                Some(span(file_value)),
                "template manifest artifact file must be a string",
            ));
            continue;
        };
        if file_path.chars().any(char::is_whitespace) {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                file_pointer,
                Some(span(file_value)),
                "template manifest artifact file must not contain whitespace",
            ));
            continue;
        }
        if Path::new(file_path).extension().is_none() {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                file_pointer,
                Some(span(file_value)),
                "template manifest artifact file must include an extension",
            ));
            continue;
        }
        if require_local_file_name
            && Path::new(file_path)
                .file_name()
                .and_then(|name| name.to_str())
                != Some(file_path)
        {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                file_pointer,
                Some(span(file_value)),
                "template manifest artifact file must be in the workflow folder",
            ));
            continue;
        }
        if check_files && matches!(exact_file_exists(base, Path::new(file_path)), Some(false)) {
            diagnostics.push(Diagnostic::error(
                "template-manifest-missing-file",
                &manifest.path,
                file_pointer,
                Some(span(file_value)),
                format!("template manifest artifact file '{file_path}' was not found"),
            ));
        }
    }
    if require_workflow_artifact && !has_workflow_artifact {
        diagnostics.push(Diagnostic::error(
            "template-manifest-missing-field",
            &manifest.path,
            "/artifacts",
            Some(span(artifacts)),
            "template manifest artifacts must include a workflow artifact",
        ));
    }
}

fn validate_template_manifest_kinds(manifest: &JsonFile, diagnostics: &mut Vec<Diagnostic>) {
    let Some(kinds) = get(&manifest.value, "kinds") else {
        return;
    };
    let Some(entries) = kinds.as_span_array() else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            "/kinds",
            Some(span(kinds)),
            "template manifest kinds must be an array",
        ));
        return;
    };
    for (index, kind) in entries.iter().enumerate() {
        let pointer = pointer_join("/kinds", &index.to_string());
        let Some(text) = as_string(kind) else {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                pointer,
                Some(span(kind)),
                "template manifest kind must be a string",
            ));
            continue;
        };
        if !matches!(text, "stateful" | "stateless") {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                pointer,
                Some(span(kind)),
                format!("template manifest kind '{text}' is not supported"),
            ));
        }
    }
}

fn validate_template_markdown_field(
    manifest: &JsonFile,
    field: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some(value) = get(&manifest.value, field) {
        validate_template_markdown_value(manifest, value, &pointer_join("", field), diagnostics);
    }
}

fn validate_template_optional_markdown_field(
    manifest: &JsonFile,
    field: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(&manifest.value, field) else {
        return;
    };
    if as_string(value).is_none() {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            pointer_join("", field),
            Some(span(value)),
            format!("template manifest {field} must be a string"),
        ));
        return;
    }
    validate_template_markdown_value(manifest, value, &pointer_join("", field), diagnostics);
}

fn validate_template_markdown_value(
    manifest: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(text) = as_string(value) else {
        return;
    };
    if markdown_link_has_spacing(text) {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            pointer.to_owned(),
            Some(span(value)),
            "template manifest markdown links must not contain whitespace between ']' and '('",
        ));
    }
}

fn markdown_link_has_spacing(text: &str) -> bool {
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != ']' {
            continue;
        }
        let mut has_whitespace = false;
        while chars.peek().is_some_and(|ch| ch.is_whitespace()) {
            has_whitespace = true;
            chars.next();
        }
        if has_whitespace && chars.peek() == Some(&'(') {
            return true;
        }
    }
    false
}

fn validate_template_manifest_images(manifest: &JsonFile, diagnostics: &mut Vec<Diagnostic>) {
    let Some(images) = get(&manifest.value, "images") else {
        return;
    };
    let Some(object) = as_object(images) else {
        return;
    };
    let base = manifest.path.parent().unwrap_or_else(|| Path::new(""));
    for required in ["light", "dark"] {
        if !object.contains_key(required) {
            diagnostics.push(Diagnostic::error(
                "template-manifest-missing-field",
                &manifest.path,
                pointer_join("/images", required),
                Some(span(images)),
                format!("template manifest images is missing required field '{required}'"),
            ));
        }
    }
    for (name, image) in object.iter() {
        let pointer = pointer_join("/images", name);
        if !matches!(name.as_str(), "light" | "dark") {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                pointer.clone(),
                Some(span(image)),
                format!("template manifest image key '{name}' is not supported"),
            ));
        }
        if name.chars().any(char::is_whitespace) {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                pointer.clone(),
                Some(span(image)),
                format!("template manifest image name '{name}' must not contain whitespace"),
            ));
        }
        let Some(image_path) = as_string(image) else {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                pointer,
                Some(span(image)),
                "template manifest image reference must be a string",
            ));
            continue;
        };
        if image_path.ends_with(".png") {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                pointer.clone(),
                Some(span(image)),
                "template manifest image reference must omit the .png extension",
            ));
            continue;
        }
        if !valid_template_image_reference(image_path) {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-value",
                &manifest.path,
                pointer.clone(),
                Some(span(image)),
                "template manifest image reference must use lowercase letters, hyphens, or underscores",
            ));
            continue;
        }
        let image_file = format!("{image_path}.png");
        if matches!(exact_file_exists(base, Path::new(&image_file)), Some(false)) {
            diagnostics.push(Diagnostic::error(
                "template-manifest-missing-file",
                &manifest.path,
                pointer,
                Some(span(image)),
                format!("template manifest image file '{image_file}' was not found"),
            ));
        }
    }
}

fn valid_template_image_reference(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-' || byte == b'_')
}

/// Case-sensitive file existence check.
///
/// Returns `Some(true)` when the file exists exactly as spelled, `Some(false)`
/// when a component along the path is confirmed absent, and `None` when a
/// filesystem error (permission denied, unreadable entry, etc.) prevents a
/// definitive answer. Callers must skip the "missing file" diagnostic on
/// `None` so that transient I/O trouble does not surface as a spec violation.
fn exact_file_exists(base: &Path, relative: &Path) -> Option<bool> {
    let mut current = base.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(expected) = component else {
            return Some(false);
        };
        let entries = match std::fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(false),
            Err(_) => return None,
        };
        let mut found = None;
        for entry in entries {
            let entry = entry.ok()?;
            if entry.file_name() == expected {
                found = Some(entry);
                break;
            }
        }
        let Some(entry) = found else {
            return Some(false);
        };
        current = entry.path();
    }
    Some(current.is_file())
}

fn validate_template_manifest_required_top_level_field(
    manifest: &JsonFile,
    field: &str,
    type_message: &'static str,
    valid: impl Fn(&json_spanned_value::spanned::Value) -> bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let field_pointer = pointer_join("", field);
    match get(&manifest.value, field) {
        Some(value) if valid(value) => {}
        Some(value) => diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            field_pointer,
            Some(span(value)),
            type_message,
        )),
        None => diagnostics.push(Diagnostic::error(
            "template-manifest-missing-field",
            &manifest.path,
            field_pointer,
            Some(span(&manifest.value)),
            format!("template manifest is missing required field '{field}'"),
        )),
    }
}

fn validate_template_manifest_optional_top_level_field(
    manifest: &JsonFile,
    field: &str,
    type_message: &'static str,
    valid: impl Fn(&json_spanned_value::spanned::Value) -> bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(&manifest.value, field) else {
        return;
    };
    if !valid(value) {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            pointer_join("", field),
            Some(span(value)),
            type_message,
        ));
    }
}

/// Lightweight shape check for a container manifest — one that neither
/// looks like a package nor a workflow manifest. We do not know its exact
/// role, so we only enforce container-level parameter/connection type shape
/// rather than the full required-field checklist.
pub(super) fn template_manifest_container_diagnostics(manifest: &JsonFile) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    match get(&manifest.value, "parameters") {
        Some(parameters) if parameters.as_span_array().is_none() => {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                "/parameters",
                Some(span(parameters)),
                "template manifest parameters must be an array",
            ));
        }
        Some(_) => {}
        None => {}
    }
    match get(&manifest.value, "connections") {
        Some(connections)
            if as_object(connections).is_none() && connections.as_span_array().is_none() =>
        {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                "/connections",
                Some(span(connections)),
                "template manifest connections must be an object or array",
            ));
        }
        Some(_) => {}
        None => diagnostics.push(Diagnostic::error(
            "template-manifest-missing-field",
            &manifest.path,
            "/connections",
            Some(span(&manifest.value)),
            "template manifest is missing required field 'connections'",
        )),
    }
    diagnostics
}

fn validate_template_parameter_entry(
    manifest: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for field in ["name", "displayName", "type", "description"] {
        let field_pointer = pointer_join(pointer, field);
        let Some(field_value) = get(value, field) else {
            diagnostics.push(Diagnostic::error(
                "template-manifest-missing-field",
                &manifest.path,
                field_pointer,
                Some(span(value)),
                format!("template manifest parameter is missing required field '{field}'"),
            ));
            continue;
        };
        if as_string(field_value).is_none() {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                field_pointer,
                Some(span(field_value)),
                format!("template manifest parameter field '{field}' must be a string"),
            ));
        }
    }
    let required_pointer = pointer_join(pointer, "required");
    match get(value, "required") {
        Some(required) if required.as_bool().is_some() => {}
        Some(required) => diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            required_pointer,
            Some(span(required)),
            "template manifest parameter field 'required' must be a boolean",
        )),
        None => diagnostics.push(Diagnostic::error(
            "template-manifest-missing-field",
            &manifest.path,
            required_pointer,
            Some(span(value)),
            "template manifest parameter is missing required field 'required'",
        )),
    }

    if let Some(name) = get(value, "name").and_then(as_string) {
        validate_template_manifest_name(
            manifest,
            name,
            &pointer_join(pointer, "name"),
            get(value, "name").map(span),
            "parameter",
            diagnostics,
        );
    }
    if let Some(display_name) = get(value, "displayName").and_then(as_string)
        && display_name.chars().next().is_some_and(char::is_lowercase)
    {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            pointer_join(pointer, "displayName"),
            get(value, "displayName").map(span),
            "template manifest parameter displayName must start with an uppercase character",
        ));
    }
    if let Some(parameter_type) = get(value, "type").and_then(as_string)
        && !matches!(
            parameter_type,
            "String" | "Bool" | "Array" | "Float" | "Int" | "Object"
        )
    {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            pointer_join(pointer, "type"),
            get(value, "type").map(span),
            format!("template manifest parameter type '{parameter_type}' is not supported"),
        ));
    }
    validate_template_parameter_allowed_values(manifest, value, pointer, diagnostics);
}

fn validate_template_parameter_allowed_values(
    manifest: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(allowed_values) = get(value, "allowedValues") else {
        return;
    };
    let allowed_values_pointer = pointer_join(pointer, "allowedValues");
    let Some(entries) = allowed_values.as_span_array() else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            allowed_values_pointer,
            Some(span(allowed_values)),
            "template manifest parameter allowedValues must be an array",
        ));
        return;
    };
    for (index, entry) in entries.iter().enumerate() {
        let entry_pointer = pointer_join(&allowed_values_pointer, &index.to_string());
        if as_object(entry).is_none() {
            diagnostics.push(Diagnostic::error(
                "template-manifest-invalid-type",
                &manifest.path,
                entry_pointer,
                Some(span(entry)),
                "template manifest parameter allowedValues entry must be an object",
            ));
            continue;
        }
        for field in ["value", "displayName"] {
            let field_pointer = pointer_join(&entry_pointer, field);
            let Some(field_value) = get(entry, field) else {
                diagnostics.push(Diagnostic::error(
                    "template-manifest-missing-field",
                    &manifest.path,
                    field_pointer,
                    Some(span(entry)),
                    format!(
                        "template manifest parameter allowedValues entry is missing required field '{field}'"
                    ),
                ));
                continue;
            };
            if as_string(field_value).is_none() {
                diagnostics.push(Diagnostic::error(
                    "template-manifest-invalid-type",
                    &manifest.path,
                    field_pointer,
                    Some(span(field_value)),
                    format!(
                        "template manifest parameter allowedValues field '{field}' must be a string"
                    ),
                ));
            }
        }
    }
}

fn validate_template_connection_connector_id(
    manifest: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(connector_id_value) = get(value, "connectorId") else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-missing-field",
            &manifest.path,
            pointer.to_owned(),
            Some(span(value)),
            "template manifest connection is missing required field 'connectorId'",
        ));
        return;
    };
    let Some(connector_id) = as_string(connector_id_value) else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            pointer.to_owned(),
            Some(span(connector_id_value)),
            "template manifest connection connectorId must be a string",
        ));
        return;
    };
    if !connector_id.starts_with('/') {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            pointer.to_owned(),
            get(value, "connectorId").map(span),
            format!("template manifest connectorId '{connector_id}' must be an absolute path"),
        ));
    }
}

fn validate_template_connection_kind(
    manifest: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(kind_value) = get(value, "kind") else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-missing-field",
            &manifest.path,
            pointer.to_owned(),
            Some(span(value)),
            "template manifest connection is missing required field 'kind'",
        ));
        return;
    };
    let Some(kind) = as_string(kind_value) else {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-type",
            &manifest.path,
            pointer.to_owned(),
            Some(span(kind_value)),
            "template manifest connection kind must be a string",
        ));
        return;
    };
    if !matches!(kind, "inapp" | "shared" | "custom") {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            pointer.to_owned(),
            Some(span(kind_value)),
            format!("template manifest connection kind '{kind}' is not supported"),
        ));
    }
}

/// Template `workflow.json` must be a bare WDL definition body — the
/// Standard `{definition, kind}` wrapper is forbidden because the template
/// runtime supplies both fields externally.
pub(super) fn template_workflow_wrapper_diagnostics(file: &JsonFile) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if let Some(definition) = get(&file.value, "definition") {
        diagnostics.push(Diagnostic::error(
            "template-workflow-invalid-wrapper",
            &file.path,
            "/definition",
            Some(span(definition)),
            "template workflow.json must contain only the workflow definition body, not the Standard definition wrapper",
        ));
    }
    if let Some(kind) = get(&file.value, "kind") {
        diagnostics.push(Diagnostic::error(
            "template-workflow-invalid-wrapper",
            &file.path,
            "/kind",
            Some(span(kind)),
            "template workflow.json must not include the Standard workflow kind wrapper field",
        ));
    }
    diagnostics
}

fn template_connection_entry_has_metadata(value: &json_spanned_value::spanned::Value) -> bool {
    // A keyed manifest entry is only evidence of a connection when the value also
    // has valid connector metadata that template manifests publish. A null/broken
    // entry must not mask a missing workflow connection reference.
    get(value, "connectorId")
        .and_then(as_string)
        .is_some_and(|connector_id| connector_id.starts_with('/'))
        && get(value, "kind")
            .and_then(as_string)
            .is_some_and(|kind| matches!(kind, "inapp" | "shared" | "custom"))
}

fn template_connection_reference_kind(
    value: &json_spanned_value::spanned::Value,
) -> Option<ConnectionReferenceKind> {
    let connector_id = get(value, "connectorId").and_then(as_string)?;
    match get(value, "kind").and_then(as_string)? {
        "inapp" if connector_id.starts_with("/serviceProviders/") => {
            Some(ConnectionReferenceKind::ServiceProvider)
        }
        "shared" | "custom" if connector_id.contains("/managedApis/") => {
            Some(ConnectionReferenceKind::ManagedApi)
        }
        _ => None,
    }
}

fn insert_template_connection_metadata(
    connections: &mut BTreeMap<String, BTreeSet<ConnectionReferenceKind>>,
    name: &str,
    kind: ConnectionReferenceKind,
) {
    connections.entry(name.to_owned()).or_default().insert(kind);
}

// Template parameters and connections are keyed by a name that must end in
// the sentinel `_#workflowname#` so the runtime can prefix per-workflow
// instantiations without collision.
fn validate_template_manifest_name(
    manifest: &JsonFile,
    name: &str,
    pointer: &str,
    source_span: Option<crate::diagnostic::ByteSpan>,
    kind: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !name.ends_with(WORKFLOW_NAME_SUFFIX) {
        diagnostics.push(Diagnostic::error(
            "template-manifest-name-missing-workflow-suffix",
            &manifest.path,
            pointer.to_owned(),
            source_span,
            format!("template manifest {kind} name '{name}' must end with _#workflowname#"),
        ));
    } else if !template_manifest_metadata_name_valid(name) {
        diagnostics.push(Diagnostic::error(
            "template-manifest-invalid-value",
            &manifest.path,
            pointer.to_owned(),
            source_span,
            format!("template manifest {kind} name '{name}' must not contain whitespace"),
        ));
    }
}

fn template_manifest_metadata_name_valid(name: &str) -> bool {
    !name.chars().any(char::is_whitespace)
}

fn template_parameter_entry_has_metadata(value: &json_spanned_value::spanned::Value) -> bool {
    ["name", "displayName", "type", "description"]
        .iter()
        .all(|field| get(value, field).and_then(as_string).is_some())
        && get(value, "required").is_some_and(|required| required.as_bool().is_some())
}

fn collect_template_connection_names(
    value: &json_spanned_value::spanned::Value,
) -> BTreeSet<String> {
    let mut connections = BTreeSet::new();
    if let Some(text) = get(value, "name").and_then(as_string) {
        if template_manifest_metadata_name_valid(text) {
            connections.insert(text.to_owned());
        }
        return connections;
    }
    if let Some(connector_id) = get(value, "connectorId").and_then(as_string)
        && let Some(connector_name) = connector_id.split('/').rfind(|segment| !segment.is_empty())
    {
        connections.insert(format!("{connector_name}_#workflowname#"));
    }
    connections
}

/// Consumption-only template workflows use a manifest-driven connections
/// model. Standard-capable ones use `parameters('$connections')` and would
/// break at runtime if that reference is present in the definition body —
/// this rule surfaces those occurrences on the Standard-capable side.
pub(super) fn template_workflow_dollar_connections_diagnostics(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for site in string_sites(value, pointer) {
        for reference in references_in_string(site.value.as_ref()) {
            if reference.kind == ReferenceKind::Parameter && reference.name == "$connections" {
                diagnostics.push(Diagnostic::error(
                    "template-workflow-invalid-connections-parameter",
                    &file.path,
                    site.pointer.clone(),
                    Some(site.span),
                    "template workflow.json must not reference parameters('$connections')",
                ));
            }
        }
    }
    diagnostics
}

/// Consumption template connection references live inside
/// `parameters('$connections')['name']['connectionId']`. Surface each such
/// string call as a synthetic connection-reference site so the manifest
/// cross-check can validate the name.
pub(super) fn template_workflow_dollar_connection_reference_sites(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
) -> Vec<ConnectionReferenceSite> {
    let mut sites = Vec::new();
    for site in string_sites(value, pointer) {
        for suffix in string_arg_function_call_suffixes_in_string(
            site.value.as_ref(),
            "parameters",
            "$connections",
        ) {
            if let Some(connection_name) = dollar_connections_connection_name(&suffix) {
                sites.push(ConnectionReferenceSite {
                    name: Some(connection_name),
                    kind: ConnectionReferenceKind::Template,
                    pointer: site.pointer.clone(),
                    span: site.span,
                });
            }
        }
    }
    sites
}

fn dollar_connections_connection_name(suffix: &str) -> Option<String> {
    let (connection_name, rest) = bracket_string_accessor(suffix)?;
    let (property, _) = bracket_string_accessor(rest)?;
    (property == "connectionId").then_some(connection_name)
}

fn bracket_string_accessor(text: &str) -> Option<(String, &str)> {
    let text = text.trim_start();
    let bytes = text.as_bytes();
    if bytes.first().copied()? != b'[' {
        return None;
    }
    let quote = *bytes.get(1)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let mut index = 2;
    let mut value = String::new();
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == quote {
            if bytes.get(index + 1).copied() == Some(b']') {
                return Some((value, &text[index + 2..]));
            }
            return None;
        }
        value.push(byte as char);
        index += 1;
    }
    None
}
