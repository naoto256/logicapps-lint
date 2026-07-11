//! Shape validator for the `Recurrence` trigger and the reusable recurrence
//! envelope embedded in other triggers (`Http`, `SlidingWindow`, polling
//! `ApiConnection`) and in Batch release criteria. Schedule sub-object
//! checks live in the sibling [`super::schedule`] module.

use super::super::materialized::arm_optional_property_absent;
use super::super::*;
use super::date::validate_recurrence_start_time_future_limit;
use super::schedule::{validate_recurrence_interval_limit, validate_recurrence_schedule};

pub(super) const RECURRENCE_FREQUENCIES: &[&str] =
    &["Second", "Minute", "Hour", "Day", "Week", "Month", "Year"];

/// Validate the `recurrence` sub-object. `frequency` + `interval` are
/// mandatory; `startTime`/`endTime`/`timeZone` are optional but interlock
/// (a bare datetime without `timeZone` must end in `Z`, and the datetime
/// must not carry an explicit UTC offset — the runtime derives it from
/// `timeZone`).
pub(in crate::check::shape) fn validate_recurrence_trigger(
    trigger: &json_spanned_value::spanned::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(recurrence) = get(trigger, "recurrence") else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(trigger_pointer, "recurrence"),
            Some(span(trigger)),
            "Recurrence trigger is missing required object field 'recurrence'",
        ));
        return;
    };
    if is_opaque_arm_expression(file, recurrence) {
        return;
    }
    if as_object(recurrence).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(trigger_pointer, "recurrence"),
            Some(span(recurrence)),
            "Recurrence trigger field 'recurrence' must be an object",
        ));
        return;
    }

    let recurrence_pointer = pointer_join(trigger_pointer, "recurrence");
    for field in ["frequency", "interval"] {
        if get(recurrence, field).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-missing-field",
                &file.path,
                pointer_join(&recurrence_pointer, field),
                Some(span(recurrence)),
                format!("Recurrence trigger is missing required field '{field}'"),
            ));
        }
    }

    if let Some(frequency) = get(recurrence, "frequency")
        && !is_opaque_arm_expression(file, frequency)
        && as_string(frequency).is_none()
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(&recurrence_pointer, "frequency"),
            Some(span(frequency)),
            "Recurrence frequency must be a string",
        ));
    } else if let Some(frequency) = get(recurrence, "frequency")
        && !is_opaque_arm_expression(file, frequency)
        && let Some(frequency_text) = as_string(frequency)
        && !wdl_string_may_match_exact(frequency_text, RECURRENCE_FREQUENCIES)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(&recurrence_pointer, "frequency"),
            get(recurrence, "frequency").map(span),
            format!("Recurrence frequency '{frequency_text}' is not supported"),
        ));
    }
    if let Some(interval) = get(recurrence, "interval")
        && !is_opaque_arm_expression(file, interval)
        && !as_string(interval).is_some_and(wdl_string_may_be_positive_integer)
        && !is_integer_value(interval)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(&recurrence_pointer, "interval"),
            Some(span(interval)),
            "Recurrence interval must be an integer",
        ));
    } else if let Some(interval) = get(recurrence, "interval")
        && !is_opaque_arm_expression(file, interval)
        && !as_string(interval).is_some_and(|text| {
            crate::wdl::WdlStringValue::classify(text)
                .literal()
                .is_none()
        })
        && !is_positive_integer_value(interval)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(&recurrence_pointer, "interval"),
            Some(span(interval)),
            "Recurrence interval must be greater than zero",
        ));
    }
    validate_recurrence_interval_limit(recurrence, &recurrence_pointer, file, diagnostics);
    validate_optional_integer_field(
        recurrence,
        &recurrence_pointer,
        "count",
        "Recurrence count",
        file,
        diagnostics,
    );
    for field in ["startTime", "endTime"] {
        validate_optional_string_field(
            recurrence,
            &recurrence_pointer,
            field,
            &format!("Recurrence {field}"),
            file,
            diagnostics,
        );
        validate_optional_recurrence_datetime(
            recurrence,
            &recurrence_pointer,
            field,
            &format!("Recurrence {field}"),
            file,
            diagnostics,
        );
    }
    validate_optional_string_field(
        recurrence,
        &recurrence_pointer,
        "timeZone",
        "Recurrence timeZone",
        file,
        diagnostics,
    );
    validate_optional_recurrence_time_zone(recurrence, &recurrence_pointer, file, diagnostics);
    validate_recurrence_schedule(recurrence, &recurrence_pointer, file, diagnostics);
}

fn validate_optional_recurrence_datetime(
    recurrence: &json_spanned_value::spanned::Value,
    recurrence_pointer: &str,
    field: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(recurrence, field) else {
        return;
    };
    if is_opaque_arm_expression(file, value) {
        return;
    }
    let Some(text) = as_string(value) else {
        return;
    };
    if wdl_string_has_dynamic_value(text) {
        return;
    }
    if !is_iso8601_datetime(text) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(recurrence_pointer, field),
            Some(span(value)),
            format!("{label} must be an ISO 8601 date-time"),
        ));
        return;
    }
    if iso8601_datetime_has_utc_offset(text) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(recurrence_pointer, field),
            Some(span(value)),
            format!("{label} must not include a UTC offset"),
        ));
        return;
    }
    let timezone_present = get(recurrence, "timeZone")
        .is_some_and(|timezone| !arm_optional_property_absent(file, timezone));
    if !timezone_present && !iso8601_datetime_has_z_suffix(text) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(recurrence_pointer, field),
            Some(span(value)),
            format!("{label} must end with 'Z' when recurrence.timeZone is not specified"),
        ));
        return;
    }
    if field == "startTime" {
        validate_recurrence_start_time_future_limit(
            text,
            recurrence_pointer,
            value,
            file,
            diagnostics,
        );
    }
}

fn validate_optional_recurrence_time_zone(
    recurrence: &json_spanned_value::spanned::Value,
    recurrence_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(recurrence, "timeZone") else {
        return;
    };
    if arm_optional_property_absent(file, value) || is_opaque_arm_expression(file, value) {
        return;
    }
    let Some(text) = as_string(value) else {
        return;
    };
    if wdl_string_has_dynamic_value(text) {
        return;
    }
    if !is_windows_time_zone(text) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(recurrence_pointer, "timeZone"),
            Some(span(value)),
            format!("Recurrence timeZone '{text}' is not a supported Windows time zone"),
        ));
    }
}

/// Validate a recurrence sub-object that is optional for the outer shape
/// (Batch release criteria). No diagnostic is emitted when the field is
/// absent.
pub(in crate::check::shape) fn validate_optional_recurrence(
    trigger: &json_spanned_value::spanned::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if get(trigger, "recurrence").is_some() {
        validate_recurrence_trigger(trigger, trigger_pointer, file, diagnostics);
    }
}
