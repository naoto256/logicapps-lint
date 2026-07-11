//! Cross-file, project-scope linting.
//!
//! While `check/workflow` looks at a workflow definition in isolation, this
//! layer needs siblings on disk: `parameters.json`, `workflowparameters.json`,
//! `connections.json`, ARM deployment templates, and LogicAppsTemplates
//! manifests. The dispatch below detects which project shape applies
//! (Standard, Consumption/ARM, Template) from filesystem cues and only runs
//! the rules relevant to that shape.
mod arm;
mod connections;
mod expressions;
mod files;
mod parameters;
mod template;
mod types;

pub(super) use arm::{
    arm_resource_diagnostics, has_logic_workflow_resource, is_arm_deployment_template,
    workflow_definitions,
};
pub(super) use files::{ProjectFiles, project_root};
pub(super) use parameters::known_parameters_for;
pub(super) use template::template_repository_manifest_diagnostics;

use self::connections::{connection_parameter_diagnostics, connection_reference_sites};
use self::parameters::{
    parameter_shape_diagnostics, project_parameter_pointer,
    standard_definition_parameter_type_diagnostics,
};
use self::template::{
    template_workflow_dollar_connection_reference_sites,
    template_workflow_dollar_connections_diagnostics,
};
use self::types::ConnectionReferenceKind;
use crate::diagnostic::Diagnostic;
use crate::json::{JsonFile, as_object, get, pointer_join, span};
use crate::workflow::extract_definition;

/// Run every project-scope rule that applies to `file`.
///
/// ARM deployment templates carry their own resource-shape checks elsewhere and
/// never contribute Standard-style parameter/connection diagnostics, so they
/// short-circuit here. Standalone workflows without a detected project root
/// also short-circuit — there is no cross-file contract to enforce.
pub(super) fn lint_project_references(file: &JsonFile, project: &ProjectFiles) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    if is_arm_deployment_template(&file.value) {
        return diagnostics;
    }

    // No project root means "single workflow, no siblings" — nothing cross-file to check.
    if !project.standard_project && !project.template_workflow {
        return diagnostics;
    }

    if project.standard_project {
        for parameters in &project.parameters {
            diagnostics.extend(parameter_shape_diagnostics(parameters));
        }

        if let Some(connections) = &project.connections {
            diagnostics.extend(connection_parameter_diagnostics(connections, project));
        }
    }

    for candidate in workflow_definitions(file) {
        let definition = candidate.effective_value();
        let workflow =
            extract_definition(definition, &candidate.pointer, candidate.effective_kind());
        let known_project_parameters = project.known_parameter_names();

        if project.template_workflow && project.template_standard_capable {
            diagnostics.extend(template_workflow_dollar_connections_diagnostics(
                file,
                definition,
                &candidate.pointer,
            ));
        }
        if project.standard_project {
            diagnostics.extend(standard_definition_parameter_type_diagnostics(
                file,
                definition,
                &candidate.pointer,
            ));
        }

        // Definition parameters and project parameters are separate contracts in
        // Standard projects: the workflow declares names, parameters.json
        // supplies deployment-time values.
        if project.standard_project && !project.parameter_source_unreadable {
            for parameter in workflow
                .parameters
                .iter()
                .filter(|name| name.as_str() != "$connections")
            {
                let has_value = known_project_parameters.contains(parameter.as_str());
                if !has_value {
                    if let Some(parameters) = project.parameters.first() {
                        let pointer = project_parameter_pointer(parameters, parameter);
                        diagnostics.push(Diagnostic::error(
                            "project-missing-root-parameter",
                            &parameters.path,
                            pointer,
                            get(&parameters.value, "parameters").map(span),
                            format!(
                                "project parameter files do not define a value for '{parameter}'"
                            ),
                        ));
                    } else {
                        let pointer = pointer_join(
                            &pointer_join(&candidate.pointer, "parameters"),
                            parameter,
                        );
                        diagnostics.push(Diagnostic::error(
                            "project-missing-root-parameter",
                            &file.path,
                            pointer.clone(),
                            workflow.node_at(&pointer).map(span),
                            format!(
                                "project parameter files do not define a value for '{parameter}'"
                            ),
                        ));
                    }
                }
            }
        }

        // Every workflow has "hard" connection references (host/service-provider/function
        // in inputs). Consumption-only template workflows additionally reference
        // connections through `parameters('$connections')['name']['connectionId']`.
        let mut connection_refs = connection_reference_sites(candidate.value, &candidate.pointer);
        if project.template_workflow && !project.template_standard_capable {
            connection_refs.extend(template_workflow_dollar_connection_reference_sites(
                candidate.value,
                &candidate.pointer,
            ));
        }
        for site in connection_refs.iter().filter(|site| site.name.is_none()) {
            diagnostics.push(Diagnostic::error(
                "project-connection-reference-invalid-type",
                &file.path,
                site.pointer.clone(),
                Some(site.span),
                "workflow connection reference fields must be strings",
            ));
        }
        // Missing-connection diagnostics require both a workflow reference and
        // a readable nearest source; otherwise the parse/I/O error is the signal.
        if connection_refs.iter().all(|site| site.name.is_none())
            || project.connection_source_unreadable
        {
            continue;
        }
        let managed_connections = project
            .connections
            .as_ref()
            .and_then(|file| get(&file.value, "managedApiConnections"))
            .and_then(as_object);
        let service_provider_connections = project
            .connections
            .as_ref()
            .and_then(|file| get(&file.value, "serviceProviderConnections"))
            .and_then(as_object);
        let function_connections = project
            .connections
            .as_ref()
            .and_then(|file| get(&file.value, "functionConnections"))
            .and_then(as_object);
        for site in connection_refs {
            let Some(reference_name) = site.name else {
                continue;
            };
            let section_known = match site.kind {
                ConnectionReferenceKind::ManagedApi => managed_connections
                    .and_then(|object| object.get(reference_name.as_str()))
                    .is_some_and(|entry| !entry.is_null()),
                ConnectionReferenceKind::ServiceProvider => service_provider_connections
                    .and_then(|object| object.get(reference_name.as_str()))
                    .is_some_and(|entry| !entry.is_null()),
                ConnectionReferenceKind::Function => function_connections
                    .and_then(|object| object.get(reference_name.as_str()))
                    .is_some_and(|entry| !entry.is_null()),
                ConnectionReferenceKind::Template => false,
            };
            let template_known = project
                .template_connections
                .get(&reference_name)
                .is_some_and(|kinds| {
                    site.kind == ConnectionReferenceKind::Template || kinds.contains(&site.kind)
                });
            let known = section_known || template_known;
            if !known {
                diagnostics.push(Diagnostic::error(
                    "project-missing-connection-reference",
                    &file.path,
                    site.pointer,
                    Some(site.span),
                    format!(
                        "project connection sources do not define connection '{reference_name}'"
                    ),
                ));
            }
        }
    }

    diagnostics
}
