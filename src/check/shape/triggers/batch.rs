//! Shape validator for the `Batch` trigger — the receiver side of a batch
//! flow. Shares the inputs shape with the `Batch` action, differing only in
//! that `inputs.mode` is Consumption-only.

use super::super::actions::integration::{validate_batch_inputs, validate_batch_mode};
use super::super::*;

/// Validate a `Batch` trigger. In Standard workflows `inputs.mode` is not
/// accepted (the runtime always uses IntegrationAccount there); Consumption
/// still exposes the Inline/IntegrationAccount switch.
pub(in crate::check::shape) fn validate_batch_trigger(
    trigger: &json_spanned_value::spanned::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_trigger_inputs_object(trigger, trigger_pointer, file, diagnostics)
    else {
        return;
    };
    let inputs_pointer = pointer_join(trigger_pointer, "inputs");
    if workflow.is_standard() {
        if let Some(mode) = get(inputs, "mode") {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &file.path,
                pointer_join(&inputs_pointer, "mode"),
                Some(span(mode)),
                "Batch trigger inputs.mode is supported only in Consumption workflows",
            ));
        }
    } else {
        validate_batch_mode(inputs, &inputs_pointer, file, diagnostics);
    }
    validate_batch_inputs(inputs, &inputs_pointer, file, diagnostics);
}
