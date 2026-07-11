//! Shared trigger-level fields validated for every trigger type: `splitOn`,
//! `conditions`, `correlation`, and `splitOnConfiguration`. Kept separate
//! from the per-type validators so each trigger dispatcher only pays the
//! cost of these checks once.

use super::super::materialized::arm_optional_property_absent;
use super::super::*;

/// Validate trigger fields that are not tied to a specific trigger type.
/// Notable rule: `splitOn` is rejected on Recurrence triggers because there
/// is no payload array to split.
pub(in crate::check::shape) fn validate_trigger_common_fields(
    trigger: &json_spanned_value::spanned::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some(split_on) = get(trigger, "splitOn")
        && !arm_optional_property_absent(file, split_on)
        && !is_opaque_arm_expression(file, split_on)
    {
        let split_on_pointer = pointer_join(trigger_pointer, "splitOn");
        if as_string(split_on).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                split_on_pointer,
                Some(span(split_on)),
                "trigger splitOn must be a string",
            ));
        } else if get(trigger, "type")
            .and_then(as_string)
            .is_some_and(|trigger_type| trigger_type.eq_ignore_ascii_case("Recurrence"))
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &file.path,
                split_on_pointer,
                Some(span(split_on)),
                "Recurrence triggers do not support splitOn",
            ));
        }
    }
    if let Some(conditions) = get(trigger, "conditions")
        && !arm_optional_property_absent(file, conditions)
        && !is_opaque_arm_expression(file, conditions)
    {
        let conditions_pointer = pointer_join(trigger_pointer, "conditions");
        if let Some(condition_values) = conditions.as_span_array() {
            for (index, condition) in condition_values.iter().enumerate() {
                let condition_pointer = pointer_join(&conditions_pointer, &index.to_string());
                if is_opaque_arm_expression(file, condition) {
                    continue;
                }
                if as_object(condition).is_none() {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-invalid-type",
                        &file.path,
                        condition_pointer,
                        Some(span(condition)),
                        "trigger condition entries must be objects",
                    ));
                    continue;
                }
                if let Some(expression) = get(condition, "expression")
                    && !arm_optional_property_absent(file, expression)
                    && !is_opaque_arm_expression(file, expression)
                    && as_string(expression).is_none()
                {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-invalid-type",
                        &file.path,
                        pointer_join(&condition_pointer, "expression"),
                        Some(span(expression)),
                        "trigger condition expression must be a string",
                    ));
                }
                if let Some(depends_on) = get(condition, "dependsOn")
                    && !arm_optional_property_absent(file, depends_on)
                    && !is_opaque_arm_expression(file, depends_on)
                    && as_string(depends_on).is_none()
                {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-invalid-type",
                        &file.path,
                        pointer_join(&condition_pointer, "dependsOn"),
                        Some(span(depends_on)),
                        "trigger condition dependsOn must be a string",
                    ));
                }
            }
        } else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                conditions_pointer,
                Some(span(conditions)),
                "trigger conditions must be an array",
            ));
        }
    }
    if let Some(correlation) = get(trigger, "correlation")
        && !arm_optional_property_absent(file, correlation)
        && !is_opaque_arm_expression(file, correlation)
    {
        let correlation_pointer = pointer_join(trigger_pointer, "correlation");
        if as_object(correlation).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                correlation_pointer,
                Some(span(correlation)),
                "trigger correlation must be an object",
            ));
        } else {
            validate_optional_string_field(
                correlation,
                &correlation_pointer,
                "clientTrackingId",
                "trigger correlation.clientTrackingId",
                file,
                diagnostics,
            );
        }
    }
    if let Some(split_on_configuration) = get(trigger, "splitOnConfiguration")
        && !arm_optional_property_absent(file, split_on_configuration)
        && !is_opaque_arm_expression(file, split_on_configuration)
    {
        let split_pointer = pointer_join(trigger_pointer, "splitOnConfiguration");
        if as_object(split_on_configuration).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                split_pointer,
                Some(span(split_on_configuration)),
                "trigger splitOnConfiguration must be an object",
            ));
        } else if let Some(correlation) = get(split_on_configuration, "correlation")
            && !arm_optional_property_absent(file, correlation)
            && !is_opaque_arm_expression(file, correlation)
        {
            let correlation_pointer = pointer_join(&split_pointer, "correlation");
            if as_object(correlation).is_none() {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-type",
                    &file.path,
                    correlation_pointer,
                    Some(span(correlation)),
                    "trigger splitOnConfiguration.correlation must be an object",
                ));
            } else {
                validate_optional_string_field(
                    correlation,
                    &correlation_pointer,
                    "clientTrackingId",
                    "trigger splitOnConfiguration.correlation.clientTrackingId",
                    file,
                    diagnostics,
                );
            }
        }
    }
}
