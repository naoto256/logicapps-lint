//! Shape validators for the integration / B2B action family: `Batch`,
//! `SendToBatch`, `FlatFileEncoding`/`FlatFileDecoding`, `Liquid`,
//! `IntegrationAccountArtifactLookup`, `XmlValidation`, `Xslt`, and
//! `Workflow` (invoke a sibling workflow). These share Integration Account
//! artifact plumbing (see [`validate_integration_account_content_inputs`]).

use super::super::materialized::arm_optional_property_absent;
use super::*;
use crate::check::shape::http::{RetryPolicyIntervalBounds, validate_http_inputs};

const FLAT_FILE_EMPTY_NODE_GENERATION_MODES: &[&str] =
    &["ForcedDisabled", "ForcedEnabled", "HonorSchemaNodeProperty"];
const BATCH_MODES: &[&str] = &["Inline", "IntegrationAccount"];
const ARTIFACT_TYPES: &[&str] = &["Agreement", "Map", "Partner", "Schema"];
const LIQUID_KINDS: &[&str] = &["JsonToJson", "JsonToText", "XmlToJson", "XmlToText"];

/// Validate a `SendToBatch` action: pushes a message into a batch receiver
/// workflow identified by `host.workflow.id` + `host.triggerName`.
pub(in crate::check::shape) fn validate_send_to_batch_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    let inputs_pointer = pointer_join(action_pointer, "inputs");
    require_object_field(inputs, &inputs_pointer, "host", file, diagnostics);
    if let Some(host) = get(inputs, "host")
        && as_object(host).is_some()
    {
        let host_pointer = pointer_join(&inputs_pointer, "host");
        require_typed_field(
            host,
            &host_pointer,
            "triggerName",
            "SendToBatch inputs.host.triggerName must be a string",
            file,
            diagnostics,
            |value| as_string(value).is_some(),
        );
        require_object_field(host, &host_pointer, "workflow", file, diagnostics);
        if let Some(workflow) = get(host, "workflow")
            && as_object(workflow).is_some()
        {
            require_typed_field(
                workflow,
                &pointer_join(&host_pointer, "workflow"),
                "id",
                "SendToBatch inputs.host.workflow.id must be a string",
                file,
                diagnostics,
                |value| as_string(value).is_some(),
            );
        }
    }
    require_typed_field(
        inputs,
        &inputs_pointer,
        "batchName",
        "SendToBatch inputs.batchName must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    require_typed_field(
        inputs,
        &inputs_pointer,
        "content",
        "SendToBatch inputs.content must be present",
        file,
        diagnostics,
        |_| true,
    );
    validate_optional_string_field(
        inputs,
        &inputs_pointer,
        "partitionName",
        "SendToBatch inputs.partitionName",
        file,
        diagnostics,
    );
    validate_optional_string_field(
        inputs,
        &inputs_pointer,
        "messageId",
        "SendToBatch inputs.messageId",
        file,
        diagnostics,
    );
}

/// Validate a `Batch` action: the batch receiver-side shape. Shared with
/// the `Batch` trigger via [`validate_batch_inputs`]/[`validate_batch_mode`].
pub(in crate::check::shape) fn validate_batch_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    validate_batch_mode(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        file,
        diagnostics,
    );
    validate_batch_inputs(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        file,
        diagnostics,
    );
}

/// Validate `Batch.inputs.mode`: `Inline` (workflow-local) or
/// `IntegrationAccount` (backed by an Integration Account batch config).
pub(in crate::check::shape) fn validate_batch_mode(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_optional_string_enum(
        inputs,
        inputs_pointer,
        "mode",
        "Batch inputs.mode",
        BATCH_MODES,
        file,
        diagnostics,
    );
}

/// Shared Batch inputs: host binding, batch/group names, release criteria,
/// and optional per-partition configurations. `content` must not be an
/// explicit `null` (though the field itself is optional on the trigger).
pub(in crate::check::shape) fn validate_batch_inputs(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_optional_object_field(
        inputs,
        inputs_pointer,
        "host",
        "Batch inputs.host",
        file,
        diagnostics,
    );
    validate_optional_string_field(
        inputs,
        inputs_pointer,
        "batchName",
        "Batch inputs.batchName",
        file,
        diagnostics,
    );
    validate_optional_string_field(
        inputs,
        inputs_pointer,
        "batchGroupName",
        "Batch inputs.batchGroupName",
        file,
        diagnostics,
    );
    validate_batch_release_criteria(inputs, inputs_pointer, file, diagnostics);
    validate_batch_configurations(inputs, inputs_pointer, file, diagnostics);
    if let Some(content) = get(inputs, "content")
        && !is_opaque_arm_expression(file, content)
        && content.is_null()
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(inputs_pointer, "content"),
            Some(span(content)),
            "Batch inputs.content must not be null",
        ));
    }
}

fn validate_batch_configurations(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(configurations) = get(inputs, "configurations") else {
        return;
    };
    if arm_optional_property_absent(file, configurations)
        || is_opaque_arm_expression(file, configurations)
    {
        return;
    }
    let configurations_pointer = pointer_join(inputs_pointer, "configurations");
    if let Some(object) = as_object(configurations) {
        for (name, configuration) in object.iter() {
            validate_batch_configuration(
                configuration,
                &pointer_join(&configurations_pointer, name),
                file,
                diagnostics,
            );
        }
    } else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            configurations_pointer,
            Some(span(configurations)),
            "Batch inputs.configurations must be an object",
        ));
    }
}

fn validate_batch_configuration(
    configuration: &json_spanned_value::spanned::Value,
    configuration_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if is_opaque_arm_expression(file, configuration) {
        return;
    }
    if as_object(configuration).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            configuration_pointer.to_owned(),
            Some(span(configuration)),
            "Batch inputs.configurations entries must be objects",
        ));
        return;
    }
    validate_batch_release_criteria(configuration, configuration_pointer, file, diagnostics);
}

// Batch release criteria bound the receiver: `messageCount` caps at 8000
// messages per batch, `batchSize` caps at 80 MiB of aggregate payload, and
// a `recurrence` of frequency `Second` must have interval >= 60 (the
// scheduler will otherwise starve the release loop).
fn validate_batch_release_criteria(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(criteria) = get(inputs, "releaseCriteria") else {
        return;
    };
    if arm_optional_property_absent(file, criteria) || is_opaque_arm_expression(file, criteria) {
        return;
    }
    let criteria_pointer = pointer_join(inputs_pointer, "releaseCriteria");
    if as_object(criteria).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            criteria_pointer,
            Some(span(criteria)),
            "Batch inputs.releaseCriteria must be an object",
        ));
        return;
    }
    for field in ["batchSize", "messageCount"] {
        validate_optional_positive_integer(
            criteria,
            &criteria_pointer,
            field,
            &format!("Batch inputs.releaseCriteria.{field}"),
            file,
            diagnostics,
        );
    }
    if let Some(message_count) = get(criteria, "messageCount")
        && !is_opaque_arm_expression(file, message_count)
        && let Some(count) = integer_value(message_count)
        && count > 8000
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(&criteria_pointer, "messageCount"),
            Some(span(message_count)),
            format!("Batch inputs.releaseCriteria.messageCount value {count} exceeds maximum 8000"),
        ));
    }
    if let Some(batch_size) = get(criteria, "batchSize")
        && !is_opaque_arm_expression(file, batch_size)
        && let Some(size) = integer_value(batch_size)
        && size > 80 * 1024 * 1024
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(&criteria_pointer, "batchSize"),
            Some(span(batch_size)),
            format!("Batch inputs.releaseCriteria.batchSize value {size} exceeds maximum 83886080"),
        ));
    }
    super::super::triggers::validate_optional_recurrence(
        criteria,
        &criteria_pointer,
        file,
        diagnostics,
    );
    if let Some(recurrence) = get(criteria, "recurrence")
        && !is_opaque_arm_expression(file, recurrence)
        && as_object(recurrence).is_some()
        && get(recurrence, "frequency").and_then(as_string) == Some("Second")
        && let Some(interval) = get(recurrence, "interval")
        && !is_opaque_arm_expression(file, interval)
        && let Some(interval_value) = integer_value(interval)
        && interval_value < 60
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(&pointer_join(&criteria_pointer, "recurrence"), "interval"),
            Some(span(interval)),
            "Batch inputs.releaseCriteria.recurrence interval must be at least 60 seconds",
        ));
    }
}

/// Validate a `Workflow` action (invoke a sibling Logic App workflow).
/// `host.workflow.id` identifies the target; `host.id` is the legacy
/// spelling and skips the workflow sub-object requirement.
pub(in crate::check::shape) fn validate_workflow_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    require_object_field(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "host",
        file,
        diagnostics,
    );
    let Some(host) = get(inputs, "host") else {
        return;
    };
    if as_object(host).is_none() {
        return;
    }
    let host_pointer = pointer_join(&pointer_join(action_pointer, "inputs"), "host");
    require_typed_field(
        host,
        &host_pointer,
        "triggerName",
        "Workflow inputs.host.triggerName must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    if let Some(id) = get(host, "id")
        && !is_opaque_arm_expression(file, id)
        && as_string(id).is_none()
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(&host_pointer, "id"),
            Some(span(id)),
            "Workflow inputs.host.id must be a string",
        ));
    }
    if get(host, "id").is_none() {
        require_object_field(host, &host_pointer, "workflow", file, diagnostics);
    }
    if let Some(workflow) = get(host, "workflow") {
        if is_opaque_arm_expression(file, workflow) {
        } else {
            let workflow_pointer = pointer_join(&host_pointer, "workflow");
            if as_object(workflow).is_none() {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-type",
                    &file.path,
                    workflow_pointer,
                    Some(span(workflow)),
                    "Workflow inputs.host.workflow must be an object",
                ));
                return;
            }
            require_typed_field(
                workflow,
                &workflow_pointer,
                "id",
                "Workflow inputs.host.workflow.id must be a string",
                file,
                diagnostics,
                |value| as_string(value).is_some(),
            );
        }
    }
    validate_http_inputs(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "Workflow inputs",
        RetryPolicyIntervalBounds::for_workflow(workflow),
        file,
        diagnostics,
    );
}

/// Validate an `Xslt` action: transforms `content` through an Integration
/// Account `map` artifact. Optional `parameters` become XSL parameters and
/// must therefore be scalar (string/number/bool).
pub(in crate::check::shape) fn validate_xslt_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    require_typed_field(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "content",
        "Xslt inputs.content must be present",
        file,
        diagnostics,
        |_| true,
    );
    validate_optional_integration_account_artifact(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "map",
        file,
        diagnostics,
    );
    validate_optional_string_field(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "transformOptions",
        "Xslt inputs.transformOptions",
        file,
        diagnostics,
    );
    if let Some(parameters) = get(inputs, "parameters")
        && !is_opaque_arm_expression(file, parameters)
    {
        let parameters_pointer =
            pointer_join(&pointer_join(action_pointer, "inputs"), "parameters");
        if let Some(entries) = as_object(parameters) {
            for (name, value) in entries {
                if !is_opaque_arm_expression(file, value)
                    && as_string(value).is_none()
                    && value.as_number().is_none()
                    && value.as_bool().is_none()
                {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-invalid-type",
                        &file.path,
                        pointer_join(&parameters_pointer, name),
                        Some(span(value)),
                        "Xslt inputs.parameters values must be strings, numbers, or booleans",
                    ));
                }
            }
        } else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                parameters_pointer,
                Some(span(parameters)),
                "Xslt inputs.parameters must be an object",
            ));
        }
    }
}

/// Validate an `IntegrationAccountArtifactLookup` action: fetches a named
/// artifact of a given `artifactType`. The `artifaceName` (sic) misspelling
/// is a documented historical alias and remains accepted.
pub(in crate::check::shape) fn validate_integration_account_artifact_lookup_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    require_typed_field(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "artifactType",
        "IntegrationAccountArtifactLookup inputs.artifactType must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    validate_optional_string_enum(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "artifactType",
        "IntegrationAccountArtifactLookup inputs.artifactType",
        ARTIFACT_TYPES,
        file,
        diagnostics,
    );
    require_typed_field(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "artifactName",
        "IntegrationAccountArtifactLookup inputs.artifactName must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    validate_optional_string_field(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "artifaceName",
        "IntegrationAccountArtifactLookup inputs.artifaceName",
        file,
        diagnostics,
    );
}

/// Validate an `XmlValidation` action: validates `content` against an
/// Integration Account `schema` artifact.
pub(in crate::check::shape) fn validate_xml_validation_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    validate_integration_account_content_inputs(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "schema",
        file,
        diagnostics,
    );
}

/// Validate a `Liquid` action: transforms `content` through an Integration
/// Account `map` artifact. `kind` selects the input/output format pair.
pub(in crate::check::shape) fn validate_liquid_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_optional_kind(
        action,
        action_pointer,
        "Liquid kind",
        LIQUID_KINDS,
        file,
        diagnostics,
    );
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    validate_integration_account_content_inputs(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "map",
        file,
        diagnostics,
    );
}

/// Validate a `FlatFileEncoding`/`FlatFileDecoding` action. Both share the
/// Integration Account content shape; `emptyNodeGenerationMode` controls
/// how empty schema nodes are serialized on encode.
pub(in crate::check::shape) fn validate_flat_file_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    validate_integration_account_content_inputs(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "schema",
        file,
        diagnostics,
    );
    validate_optional_string_enum(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "emptyNodeGenerationMode",
        "FlatFileEncoding inputs.emptyNodeGenerationMode",
        FLAT_FILE_EMPTY_NODE_GENERATION_MODES,
        file,
        diagnostics,
    );
}

/// Shared Integration Account content shape: `content` (any) plus
/// `integrationAccount.<artifact_field>.name`. `artifact_field` differs by
/// action (Liquid → `map`, XmlValidation/FlatFile → `schema`).
pub(in crate::check::shape) fn validate_integration_account_content_inputs(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    artifact_field: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    require_typed_field(
        inputs,
        inputs_pointer,
        "content",
        "integration account action inputs.content must be present",
        file,
        diagnostics,
        |_| true,
    );
    require_typed_field(
        inputs,
        inputs_pointer,
        "integrationAccount",
        "integration account action inputs.integrationAccount must be an object",
        file,
        diagnostics,
        |value| as_object(value).is_some(),
    );
    let Some(integration_account) = get(inputs, "integrationAccount") else {
        return;
    };
    if as_object(integration_account).is_none() {
        return;
    }
    let integration_account_pointer = pointer_join(inputs_pointer, "integrationAccount");
    require_object_field(
        integration_account,
        &integration_account_pointer,
        artifact_field,
        file,
        diagnostics,
    );
    let Some(artifact) = get(integration_account, artifact_field) else {
        return;
    };
    if as_object(artifact).is_none() {
        return;
    }
    require_typed_field(
        artifact,
        &pointer_join(&integration_account_pointer, artifact_field),
        "name",
        "integration account artifact name must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
}

/// Like [`validate_integration_account_content_inputs`] but the entire
/// `integrationAccount` block is optional; used by Xslt where the map can
/// alternatively be inlined via `content`.
pub(in crate::check::shape) fn validate_optional_integration_account_artifact(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    artifact_field: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(integration_account) = get(inputs, "integrationAccount") else {
        return;
    };
    if as_object(integration_account).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(inputs_pointer, "integrationAccount"),
            Some(span(integration_account)),
            "integration account action inputs.integrationAccount must be an object",
        ));
        return;
    }
    let integration_account_pointer = pointer_join(inputs_pointer, "integrationAccount");
    require_object_field(
        integration_account,
        &integration_account_pointer,
        artifact_field,
        file,
        diagnostics,
    );
}
