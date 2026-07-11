//! `parameters.json` / `workflowparameters.json` validation and Standard
//! definition-parameter type checks.
//!
//! Two contracts collide in this file: Standard project parameters (the file
//! is a flat map of `{name: {type, value}}`) and workflow definition
//! parameters (declared inside the workflow itself, with a different set of
//! legal types). Rules keep them separate because a Standard project's
//! type restriction (no SecureString/SecureObject in the definition) is
//! independent of what parameters.json is allowed to contain.
use super::expressions::project_json_expression_diagnostics;
use super::files::ProjectFiles;
use crate::diagnostic::Diagnostic;
use crate::json::{JsonFile, as_object, as_string, get, pointer_join, span};
use std::collections::BTreeSet;

const STANDARD_PARAMETER_TYPES: &[&str] = &["Array", "Bool", "Float", "Int", "Object", "String"];

/// Names declared at the top level of a Standard parameter file.
pub(super) fn collect_project_parameter_names(
    value: &json_spanned_value::spanned::Value,
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for (name, _pointer, _value) in project_parameter_entries(value) {
        names.insert(name);
    }
    names
}

fn project_parameter_entries(
    value: &json_spanned_value::spanned::Value,
) -> Vec<(String, String, &json_spanned_value::spanned::Value)> {
    // Standard parameter files are keyed directly by parameter name. ARM
    // deployment-style `{ "parameters": { ... } }` files are filtered earlier
    // when they are declared deployment parameter files; schema-less wrappers
    // must not be treated as Standard parameter namespaces.
    let (base, object) = ("", as_object(value));
    let Some(object) = object else {
        return Vec::new();
    };
    object
        .iter()
        .map(|(name, value)| (name.to_string(), pointer_join(base, name), value))
        .collect()
}

pub(super) fn project_parameter_pointer(parameters: &JsonFile, name: &str) -> String {
    let _ = parameters;
    pointer_join("", name)
}

/// Names visible to expressions inside the file at `_definition_pointer`.
/// Currently uniform across the project, but the signature admits future
/// per-file scoping (e.g. template workflow local parameters).
pub(in crate::check) fn known_parameters_for(
    _file: &JsonFile,
    project: &ProjectFiles,
    _definition_pointer: &str,
) -> BTreeSet<String> {
    project.known_parameter_names()
}

/// Standard workflows forbid `SecureString` / `SecureObject` definition
/// parameter types — those are ARM/Consumption-only. Emit an error if the
/// definition uses one.
pub(super) fn standard_definition_parameter_type_diagnostics(
    file: &JsonFile,
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let Some(parameters) = get(value, "parameters").and_then(as_object) else {
        return diagnostics;
    };
    let parameters_pointer = pointer_join(pointer, "parameters");
    for (name, parameter) in parameters.iter() {
        let Some(parameter_type) = get(parameter, "type") else {
            continue;
        };
        let Some(parameter_type_text) = as_string(parameter_type) else {
            continue;
        };
        if parameter_type_text.eq_ignore_ascii_case("SecureObject")
            || parameter_type_text.eq_ignore_ascii_case("SecureString")
        {
            diagnostics.push(Diagnostic::error(
                "project-parameter-invalid-type",
                &file.path,
                pointer_join(&pointer_join(&parameters_pointer, name), "type"),
                Some(span(parameter_type)),
                format!(
                    "Standard workflow definition parameter type '{parameter_type_text}' is not supported"
                ),
            ));
        }
    }
    diagnostics
}

/// Lint a Standard parameter file: top-level object, each entry `{ type,
/// value }`, type in the supported set, and value strings against the
/// project's WDL sub-language (only `appsetting` allowed here).
pub(super) fn parameter_shape_diagnostics(parameters: &JsonFile) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if as_object(&parameters.value).is_none() {
        diagnostics.push(Diagnostic::error(
            "project-parameter-invalid-shape",
            &parameters.path,
            "",
            Some(span(&parameters.value)),
            "Standard parameter file must be an object",
        ));
        return diagnostics;
    }

    for (name, pointer, value) in project_parameter_entries(&parameters.value) {
        let object = as_object(value);
        let invalid =
            object.is_none() || get(value, "type").is_none() || get(value, "value").is_none();

        if invalid {
            diagnostics.push(Diagnostic::error(
                "project-parameter-invalid-shape",
                &parameters.path,
                pointer.clone(),
                Some(span(value)),
                parameter_shape_message(&name),
            ));
        }

        if let Some(parameter_type) = get(value, "type") {
            let type_pointer = pointer_join(&pointer, "type");
            match as_string(parameter_type) {
                Some(parameter_type_text)
                    if !standard_parameter_type_supported(parameter_type_text) =>
                {
                    diagnostics.push(Diagnostic::error(
                        "project-parameter-invalid-type",
                        &parameters.path,
                        type_pointer,
                        Some(span(parameter_type)),
                        format!("Standard parameter type '{parameter_type_text}' is not supported"),
                    ));
                }
                Some(_) => {}
                None => diagnostics.push(Diagnostic::error(
                    "project-parameter-invalid-type",
                    &parameters.path,
                    type_pointer,
                    Some(span(parameter_type)),
                    "Standard parameter type must be a string",
                )),
            }
        }

        if let Some(parameter_value) = get(value, "value") {
            let value_pointer = pointer_join(&pointer, "value");
            diagnostics.extend(project_json_expression_diagnostics(
                parameters,
                parameter_value,
                &value_pointer,
                "project-parameter-invalid-expression",
                "parameters.json",
                &["appsetting"],
            ));
        }
    }
    diagnostics
}

fn standard_parameter_type_supported(parameter_type: &str) -> bool {
    STANDARD_PARAMETER_TYPES
        .iter()
        .any(|allowed| parameter_type.eq_ignore_ascii_case(allowed))
}

fn parameter_shape_message(name: &str) -> String {
    format!("parameter '{name}' must define both type and value")
}
