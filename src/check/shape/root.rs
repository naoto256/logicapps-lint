//! Driver for shape/schema diagnostics on a single workflow definition.
//!
//! Runs, in order:
//!  1. opaque-ARM whole-definition escape hatch — if the entire definition
//!     was authored as an ARM expression, re-run against the materialized
//!     value and rebind diagnostics onto the ARM source span,
//!  2. definition-level metadata (`$schema`, `contentVersion`, `description`)
//!     and the top-level `actions` / `triggers` presence checks,
//!  3. per-section object/count/limit checks (`parameters`, `outputs`,
//!     `staticResults`, standard trigger-count),
//!  4. delegate to the trigger/action collectors which fan out into the
//!     rule modules registered in `registry.rs`.

use super::limits::*;
use super::materialized::*;
use super::operations::*;
use super::*;

/// Emit every shape/schema diagnostic for one workflow definition.
///
/// `definition_pointer` is `""` for a bare WDL file and `/properties/definition`
/// (or similar) when the workflow is embedded in an ARM template — pointer
/// joining upstream keeps every diagnostic pointer stable across both shapes.
pub(in crate::check) fn shape_diagnostics(
    file: &JsonFile,
    definition: &json_spanned_value::spanned::Value,
    definition_pointer: &str,
    workflow: &Workflow<'_>,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    known_parameters: &std::collections::BTreeSet<String>,
    definition_parameter_defaults_required: bool,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    // ARM embedded workflows can replace the entire definition with an
    // expression. If we can materialize it statically, re-run shape rules on
    // the resulting value and rebind every diagnostic's span to the ARM source
    // location so the user's editor points at the expression, not at synthetic
    // offsets inside a value that does not exist in their file.
    if is_opaque_arm_expression(file, definition) {
        if let Some((materialized, source_span)) = materialized_spanned_value(definition) {
            let materialized_workflow = crate::workflow::extract_definition_with_arm_scope(
                &materialized,
                definition_pointer,
                workflow.kind.clone(),
                arm_scope,
            );
            let materialized_diagnostics = shape_diagnostics(
                file,
                &materialized,
                definition_pointer,
                &materialized_workflow,
                arm_scope,
                known_parameters,
                definition_parameter_defaults_required,
            );
            extend_materialized_diagnostics(
                &mut diagnostics,
                materialized_diagnostics,
                source_span,
            );
        }
        return diagnostics;
    }

    if !definition_pointer.is_empty() && as_object(definition).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            definition_pointer.to_owned(),
            Some(span(definition)),
            "definition must be an object",
        ));
        return diagnostics;
    }
    validate_workflow_kind(definition_pointer, file, workflow, &mut diagnostics);

    let actions_value =
        get(definition, "actions").filter(|value| !arm_optional_property_absent(file, value));
    let triggers_value =
        get(definition, "triggers").filter(|value| !arm_optional_property_absent(file, value));

    if triggers_value.is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(definition_pointer, "triggers"),
            Some(span(definition)),
            "definition must contain triggers",
        ));
    }
    if actions_value.is_none() && triggers_value.is_none() {
        // Emit both pointers so automation can attach a fix to either missing
        // top-level section without relying on a synthetic root diagnostic.
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(definition_pointer, "actions"),
            Some(span(definition)),
            "definition must contain actions or triggers",
        ));
    }

    let root_metadata_required =
        definition_pointer.is_empty() || definition_pointer == "/definition";
    let mut missing_root_metadata = Vec::new();
    for field in ["$schema", "contentVersion"] {
        match get(definition, field) {
            Some(value) if arm_optional_property_absent(file, value) => {
                if root_metadata_required {
                    missing_root_metadata.push(field);
                }
            }
            Some(value) if !is_opaque_arm_expression(file, value) => {
                validate_root_metadata_field(
                    field,
                    value,
                    definition_pointer,
                    file,
                    &mut diagnostics,
                );
            }
            Some(_) => {}
            None if root_metadata_required => missing_root_metadata.push(field),
            None => {}
        }
    }
    if let Some(description) = get(definition, "description")
        && !arm_optional_property_absent(file, description)
        && !is_opaque_arm_expression(file, description)
    {
        match as_string(description) {
            Some(text) if text.chars().count() > 256 => {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-value",
                    &file.path,
                    pointer_join(definition_pointer, "description"),
                    Some(span(description)),
                    "definition.description exceeds the 256 character limit",
                ));
            }
            Some(_) => {}
            None => {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-type",
                    &file.path,
                    pointer_join(definition_pointer, "description"),
                    Some(span(description)),
                    "definition.description must be a string",
                ));
            }
        }
    }

    if let Some(actions) = actions_value {
        validate_definition_object_field(
            actions,
            &pointer_join(definition_pointer, "actions"),
            "definition.actions",
            file,
            &mut diagnostics,
        );
    }
    if let Some(actions) = actions_value {
        validate_root_object_count(
            actions,
            &pointer_join(definition_pointer, "actions"),
            "definition.actions",
            500,
            file,
            &mut diagnostics,
        );
    }
    validate_total_action_limits(definition_pointer, file, workflow, &mut diagnostics);

    if let Some(triggers) = triggers_value {
        validate_definition_object_field(
            triggers,
            &pointer_join(definition_pointer, "triggers"),
            "definition.triggers",
            file,
            &mut diagnostics,
        );
        if let Some((0, source_span)) = effective_object_entry_count(triggers, file) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                pointer_join(definition_pointer, "triggers"),
                Some(source_span),
                "definition.triggers must contain at least one trigger",
            ));
        }
        validate_root_object_count(
            triggers,
            &pointer_join(definition_pointer, "triggers"),
            "definition.triggers",
            10,
            file,
            &mut diagnostics,
        );
        validate_standard_trigger_count(
            triggers,
            &pointer_join(definition_pointer, "triggers"),
            file,
            workflow,
            &mut diagnostics,
        );
    }

    if let Some(parameters) = get(definition, "parameters") {
        let pointer = pointer_join(definition_pointer, "parameters");
        if validate_definition_object_field(
            parameters,
            &pointer,
            "definition.parameters",
            file,
            &mut diagnostics,
        ) {
            definition_io::validate_definition_parameters(
                parameters,
                &pointer,
                file,
                known_parameters,
                definition_parameter_defaults_required,
                &mut diagnostics,
            );
        }
    }
    if let Some(parameters) = get(definition, "parameters")
        && !arm_optional_property_absent(file, parameters)
    {
        validate_root_object_count(
            parameters,
            &pointer_join(definition_pointer, "parameters"),
            "definition.parameters",
            if workflow.is_standard() { 500 } else { 50 },
            file,
            &mut diagnostics,
        );
    }

    if let Some(outputs) = get(definition, "outputs") {
        let pointer = pointer_join(definition_pointer, "outputs");
        if validate_definition_object_field(
            outputs,
            &pointer,
            "definition.outputs",
            file,
            &mut diagnostics,
        ) {
            definition_io::validate_definition_outputs(outputs, &pointer, file, &mut diagnostics);
        }
    }
    if let Some(outputs) = get(definition, "outputs")
        && !arm_optional_property_absent(file, outputs)
    {
        validate_root_object_count(
            outputs,
            &pointer_join(definition_pointer, "outputs"),
            "definition.outputs",
            10,
            file,
            &mut diagnostics,
        );
    }

    static_results::validate_static_results(
        definition,
        definition_pointer,
        file,
        workflow,
        &mut diagnostics,
    );

    collect_action_container_shape(
        actions_value,
        &pointer_join(definition_pointer, "actions"),
        file,
        workflow,
        arm_scope,
        &mut diagnostics,
    );
    collect_trigger_shape(
        triggers_value,
        &pointer_join(definition_pointer, "triggers"),
        file,
        workflow,
        arm_scope,
        &mut diagnostics,
    );
    for field in missing_root_metadata {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(definition_pointer, field),
            Some(span(definition)),
            format!("definition is missing required field '{field}'"),
        ));
    }
    diagnostics
}

fn validate_definition_object_field(
    value: &json_spanned_value::spanned::Value,
    pointer: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) -> bool {
    if arm_optional_property_absent(file, value) {
        return false;
    }
    if is_opaque_arm_expression(file, value) {
        if let Some((value, source_span)) = static_json_value_from_spanned(file, value)
            && !value.is_object()
            && !value.is_null()
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                pointer.to_owned(),
                Some(source_span),
                format!("{label} must be an object"),
            ));
        }
        return false;
    }
    if as_object(value).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer.to_owned(),
            Some(span(value)),
            format!("{label} must be an object"),
        ));
        return false;
    }
    true
}

fn validate_root_metadata_field(
    field: &str,
    value: &json_spanned_value::spanned::Value,
    definition_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let pointer = pointer_join(definition_pointer, field);
    let Some(text) = as_string(value) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer,
            Some(span(value)),
            format!("definition.{field} must be a string"),
        ));
        return;
    };
    let valid = match field {
        "$schema" => workflow_schema_supported(text),
        "contentVersion" => workflow_content_version_supported(text),
        _ => true,
    };
    if !valid {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer,
            Some(span(value)),
            format!("definition.{field} has an unsupported value"),
        ));
    }
}

fn workflow_schema_supported(value: &str) -> bool {
    value
        == "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
}

fn workflow_content_version_supported(value: &str) -> bool {
    let mut parts = value.split('.');
    (0..4).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) && parts.next().is_none()
}

fn validate_workflow_kind(
    definition_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    // `InvalidType` skips the unsupported-value diagnostic because a separate
    // shape diagnostic already reports the non-string `kind` field.
    let Some(kind) = workflow
        .kind
        .as_ref()
        .and_then(crate::workflow::WorkflowKind::as_named)
    else {
        return;
    };
    if kind.eq_ignore_ascii_case("Stateful") || kind.eq_ignore_ascii_case("Stateless") {
        return;
    }
    diagnostics.push(Diagnostic::error(
        "workflow-shape-invalid-value",
        &file.path,
        workflow_kind_pointer(definition_pointer),
        None,
        format!("workflow kind '{kind}' is not supported"),
    ));
}

fn workflow_kind_pointer(definition_pointer: &str) -> String {
    if definition_pointer == "/definition" {
        return "/kind".to_owned();
    }
    if let Some(resource_pointer) = definition_pointer.strip_suffix("/properties/definition") {
        return pointer_join(resource_pointer, "kind");
    }
    pointer_join(definition_pointer, "kind")
}
