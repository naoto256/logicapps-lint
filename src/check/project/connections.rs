//! `connections.json` validation and workflow-side connection-reference
//! discovery.
//!
//! Split by direction: `connection_parameter_diagnostics` lints the
//! `connections.json` file itself (WDL syntax, allowed expression functions,
//! parameter references) while the `*_sites` helpers surface the
//! `connectionName` / `referenceName` fields inside a workflow definition so
//! the cross-check in `mod.rs` can verify each one has a home.
use super::expressions::invalid_project_expression_calls;
use super::files::ProjectFiles;
use super::types::{ConnectionReferenceKind, ConnectionReferenceSite};
use crate::diagnostic::Diagnostic;
use crate::json::{JsonFile, as_object, as_string, get, pointer_join, span};
use crate::wdl::{ReferenceKind, references_in_string, syntax_issues_in_string};
use crate::workflow::string_sites;

/// Lint `connections.json`: WDL syntax, expression-function allowlist, and
/// parameter references against the project's known parameter names.
pub(super) fn connection_parameter_diagnostics(
    connections: &JsonFile,
    project: &ProjectFiles,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let known_parameters = project.known_parameter_names();
    for site in string_sites(&connections.value, "") {
        for issue in syntax_issues_in_string(site.value.as_ref()) {
            diagnostics.push(Diagnostic::error(
                "wdl-syntax-error",
                &connections.path,
                site.pointer.clone(),
                Some(site.span),
                issue.message,
            ));
        }

        diagnostics.extend(invalid_project_expression_calls(
            connections,
            &site,
            "project-connection-invalid-expression",
            "connections.json",
            &["appsetting", "parameters"],
        ));

        for reference in references_in_string(site.value.as_ref()) {
            if reference.kind == ReferenceKind::Parameter
                && !project.parameter_source_unreadable
                && !known_parameters.contains(&reference.name)
            {
                diagnostics.push(Diagnostic::error(
                    "project-missing-connection-parameter",
                    &connections.path,
                    site.pointer.clone(),
                    Some(site.span),
                    format!(
                        "connections.json references missing parameter '{}'",
                        reference.name
                    ),
                ));
            }
        }
    }
    diagnostics
}

/// Every connection-reference field reachable from `value`, tagged with the
/// section it must resolve against (managed API / service provider /
/// function). Walks actions (including nested containers — Switch cases,
/// If else, Agent tools) and triggers.
pub(super) fn connection_reference_sites(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
) -> Vec<ConnectionReferenceSite> {
    let mut out = Vec::new();
    collect_action_container_connection_reference_sites(
        get(value, "actions"),
        &pointer_join(pointer, "actions"),
        &mut out,
    );
    collect_named_connection_reference_sites(
        get(value, "triggers"),
        &pointer_join(pointer, "triggers"),
        &mut out,
    );
    out
}

fn collect_action_container_connection_reference_sites(
    value: Option<&json_spanned_value::spanned::Value>,
    pointer: &str,
    out: &mut Vec<ConnectionReferenceSite>,
) {
    let Some(actions) = value.and_then(as_object) else {
        return;
    };

    for (name, action) in actions.iter() {
        let action_pointer = pointer_join(pointer, name);
        collect_single_connection_reference_site(action, &action_pointer, out);
        collect_nested_action_connection_reference_sites(action, &action_pointer, out);
    }
}

fn collect_named_connection_reference_sites(
    value: Option<&json_spanned_value::spanned::Value>,
    pointer: &str,
    out: &mut Vec<ConnectionReferenceSite>,
) {
    let Some(object) = value.and_then(as_object) else {
        return;
    };

    for (name, child) in object.iter() {
        collect_single_connection_reference_site(child, &pointer_join(pointer, name), out);
    }
}

fn collect_single_connection_reference_site(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    out: &mut Vec<ConnectionReferenceSite>,
) {
    // The three fixed shapes of an inputs-level connection reference in a
    // Standard workflow. Each path maps to the `connections.json` section
    // that must define the referenced name.
    for (path, kind) in [
        (
            ["inputs", "function", "connectionName"].as_slice(),
            ConnectionReferenceKind::Function,
        ),
        (
            ["inputs", "host", "connection", "referenceName"].as_slice(),
            ConnectionReferenceKind::ManagedApi,
        ),
        (
            ["inputs", "serviceProviderConfiguration", "connectionName"].as_slice(),
            ConnectionReferenceKind::ServiceProvider,
        ),
    ] {
        let Some((value, value_pointer)) = get_path(value, pointer, path) else {
            continue;
        };
        out.push(ConnectionReferenceSite {
            name: as_string(value).map(str::to_owned),
            kind,
            pointer: value_pointer,
            span: span(value),
        });
    }
}

fn collect_nested_action_connection_reference_sites(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    out: &mut Vec<ConnectionReferenceSite>,
) {
    collect_action_container_connection_reference_sites(
        get(value, "actions"),
        &pointer_join(pointer, "actions"),
        out,
    );

    if let Some(cases) = get(value, "cases").and_then(as_object) {
        let cases_pointer = pointer_join(pointer, "cases");
        for (case_name, case_value) in cases.iter() {
            collect_action_container_connection_reference_sites(
                get(case_value, "actions"),
                &pointer_join(&pointer_join(&cases_pointer, case_name), "actions"),
                out,
            );
        }
    }

    for branch in ["default", "else"] {
        if let Some(branch_value) = get(value, branch) {
            collect_action_container_connection_reference_sites(
                get(branch_value, "actions"),
                &pointer_join(&pointer_join(pointer, branch), "actions"),
                out,
            );
        }
    }

    if let Some(tools) = get(value, "tools").and_then(as_object) {
        let tools_pointer = pointer_join(pointer, "tools");
        for (tool_name, tool_value) in tools.iter() {
            collect_action_container_connection_reference_sites(
                get(tool_value, "actions"),
                &pointer_join(&pointer_join(&tools_pointer, tool_name), "actions"),
                out,
            );
        }
    }
}

fn get_path<'a>(
    mut value: &'a json_spanned_value::spanned::Value,
    pointer: &str,
    path: &[&str],
) -> Option<(&'a json_spanned_value::spanned::Value, String)> {
    let mut value_pointer = pointer.to_owned();
    for key in path {
        value = get(value, key)?;
        value_pointer = pointer_join(&value_pointer, key);
    }
    Some((value, value_pointer))
}
