//! Shape validators for `recurrence.schedule` and the per-frequency limits
//! on `interval`. `schedule` is the fine-grained portion of a recurrence
//! spec: `weekDays` for weekly, `monthDays`/`monthlyOccurrences` for
//! monthly, and `hours`/`minutes` for daily/weekly cadence.

use super::super::materialized::arm_optional_property_absent;
use super::super::*;
use super::recurrence::RECURRENCE_FREQUENCIES;

const RECURRENCE_WEEK_DAYS: &[&str] = &[
    "Friday",
    "Monday",
    "Saturday",
    "Sunday",
    "Thursday",
    "Tuesday",
    "Wednesday",
];

/// Validate `recurrence.schedule`. Fields interlock with `frequency`:
/// `hours`/`minutes` are Day/Week-only, `monthDays`/`monthlyOccurrences`
/// are Month-only, `weekDays` is Week-only. When `weekDays` is present the
/// scalar `hours`/`minutes` shorthand is disallowed; otherwise scalars are
/// accepted for authoring convenience.
pub(super) fn validate_recurrence_schedule(
    recurrence: &json_spanned_value::spanned::Value,
    recurrence_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(schedule) = get(recurrence, "schedule") else {
        return;
    };
    let schedule_pointer = pointer_join(recurrence_pointer, "schedule");
    if arm_optional_property_absent(file, schedule) || is_opaque_arm_expression(file, schedule) {
        return;
    }
    if as_object(schedule).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            schedule_pointer,
            Some(span(schedule)),
            "Recurrence schedule must be an object",
        ));
        return;
    }
    let frequency = get(recurrence, "frequency")
        .filter(|frequency| !is_opaque_arm_expression(file, frequency))
        .and_then(as_string)
        .filter(|frequency| string_in_exact(frequency, RECURRENCE_FREQUENCIES));
    for field in ["minutes", "hours"] {
        if let Some(value) = get(schedule, field)
            && !arm_optional_property_absent(file, value)
            && let Some(frequency) = frequency
            && frequency != "Day"
            && frequency != "Week"
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &file.path,
                pointer_join(&schedule_pointer, field),
                Some(span(value)),
                format!(
                    "Recurrence schedule.{field} is only supported when frequency is Day or Week"
                ),
            ));
        }
    }
    for field in ["monthDays", "monthlyOccurrences"] {
        if let Some(value) = get(schedule, field)
            && !arm_optional_property_absent(file, value)
            && let Some(frequency) = frequency
            && frequency != "Month"
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-context",
                &file.path,
                pointer_join(&schedule_pointer, field),
                Some(span(value)),
                format!("Recurrence schedule.{field} is only supported when frequency is Month"),
            ));
        }
    }
    let Some(week_days) = get(schedule, "weekDays") else {
        validate_integer_list_field(
            schedule,
            &schedule_pointer,
            "minutes",
            IntegerListRule {
                range: (0, 59),
                allow_string_values: true,
                allow_scalar: true,
            },
            file,
            diagnostics,
        );
        validate_integer_list_field(
            schedule,
            &schedule_pointer,
            "hours",
            IntegerListRule {
                range: (0, 23),
                allow_string_values: true,
                allow_scalar: true,
            },
            file,
            diagnostics,
        );
        validate_integer_list_field(
            schedule,
            &schedule_pointer,
            "monthDays",
            IntegerListRule {
                range: (-31, 31),
                allow_string_values: false,
                allow_scalar: false,
            },
            file,
            diagnostics,
        );
        validate_monthly_occurrences(schedule, &schedule_pointer, file, diagnostics);
        return;
    };
    validate_week_days(
        week_days,
        &pointer_join(&schedule_pointer, "weekDays"),
        file,
        diagnostics,
    );
    if let Some(frequency) = get(recurrence, "frequency")
        && !is_opaque_arm_expression(file, frequency)
        && as_string(frequency).is_some_and(|frequency| {
            string_in_exact(frequency, RECURRENCE_FREQUENCIES) && frequency != "Week"
        })
        && !arm_optional_property_absent(file, week_days)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(&schedule_pointer, "weekDays"),
            Some(span(week_days)),
            "Recurrence schedule.weekDays is only supported when frequency is Week",
        ));
    }
    validate_integer_list_field(
        schedule,
        &schedule_pointer,
        "minutes",
        IntegerListRule {
            range: (0, 59),
            allow_string_values: true,
            allow_scalar: true,
        },
        file,
        diagnostics,
    );
    validate_integer_list_field(
        schedule,
        &schedule_pointer,
        "hours",
        IntegerListRule {
            range: (0, 23),
            allow_string_values: true,
            allow_scalar: true,
        },
        file,
        diagnostics,
    );
    validate_integer_list_field(
        schedule,
        &schedule_pointer,
        "monthDays",
        IntegerListRule {
            range: (-31, 31),
            allow_string_values: false,
            allow_scalar: false,
        },
        file,
        diagnostics,
    );
    validate_monthly_occurrences(schedule, &schedule_pointer, file, diagnostics);
}

/// Validate `schedule.weekDays`. Accepts either a single-day string or an
/// array of day-name strings; each entry is matched against the fixed set
/// of long English day names.
pub(super) fn validate_week_days(
    week_days: &json_spanned_value::spanned::Value,
    week_days_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if arm_optional_property_absent(file, week_days) || is_opaque_arm_expression(file, week_days) {
        return;
    }
    if let Some(text) = as_string(week_days) {
        if !wdl_string_may_match_exact(text, RECURRENCE_WEEK_DAYS) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                week_days_pointer.to_owned(),
                Some(span(week_days)),
                format!("Recurrence schedule.weekDays value '{text}' is not supported"),
            ));
        }
        return;
    }
    let Some(values) = week_days.as_span_array() else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            week_days_pointer.to_owned(),
            Some(span(week_days)),
            "Recurrence schedule.weekDays must be a string or array",
        ));
        return;
    };
    for (index, value) in values.iter().enumerate() {
        let pointer = pointer_join(week_days_pointer, &index.to_string());
        if arm_optional_property_absent(file, value) || is_opaque_arm_expression(file, value) {
            continue;
        }
        let Some(text) = as_string(value) else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                pointer,
                Some(span(value)),
                "Recurrence schedule.weekDays entries must be strings",
            ));
            continue;
        };
        if !wdl_string_may_match_exact(text, RECURRENCE_WEEK_DAYS) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                pointer,
                Some(span(value)),
                format!("Recurrence schedule.weekDays value '{text}' is not supported"),
            ));
        }
    }
}

/// Per-frequency upper bound on `recurrence.interval`. The runtime schedules
/// against a fixed maximum queue horizon, so shorter frequencies allow much
/// larger intervals (Second: ~9.9M, Year: unbounded).
pub(super) fn validate_recurrence_interval_limit(
    recurrence: &json_spanned_value::spanned::Value,
    recurrence_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(interval) = get(recurrence, "interval") else {
        return;
    };
    if is_opaque_arm_expression(file, interval) {
        return;
    }
    let Some(interval) = integer_value(interval) else {
        return;
    };
    let Some(frequency) = get(recurrence, "frequency").and_then(as_string) else {
        return;
    };
    let Some(max) = recurrence_interval_max(frequency) else {
        return;
    };
    if interval > max {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(recurrence_pointer, "interval"),
            get(recurrence, "interval").map(span),
            format!("Recurrence interval {interval} exceeds maximum {max} for {frequency}"),
        ));
    }
}

fn recurrence_interval_max(frequency: &str) -> Option<i64> {
    match frequency {
        "Second" => Some(9_999_999),
        "Minute" => Some(72_000),
        "Hour" => Some(12_000),
        "Day" => Some(500),
        "Week" => Some(71),
        "Month" => Some(16),
        "Year" => None,
        _ => None,
    }
}

/// Validate a schedule integer list (`minutes`/`hours`/`monthDays`).
/// `rule.allow_scalar` permits authoring shorthand (`hours: 9`);
/// `rule.allow_string_values` accepts numeric-in-string variants.
pub(super) fn validate_integer_list_field(
    object: &json_spanned_value::spanned::Value,
    object_pointer: &str,
    field: &str,
    rule: IntegerListRule,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(object, field) else {
        return;
    };
    if arm_optional_property_absent(file, value) || is_opaque_arm_expression(file, value) {
        return;
    }
    let field_pointer = pointer_join(object_pointer, field);
    if as_string(value).is_some_and(wdl_string_is_full_expression) {
        return;
    }
    if let Some(values) = value.as_span_array() {
        for (index, entry) in values.iter().enumerate() {
            validate_schedule_integer_value(
                entry,
                &pointer_join(&field_pointer, &index.to_string()),
                field,
                rule,
                file,
                diagnostics,
            );
        }
        return;
    }
    if !rule.allow_scalar {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            field_pointer,
            Some(span(value)),
            format!("Recurrence schedule.{field} must be an array"),
        ));
        return;
    }
    validate_schedule_integer_value(value, &field_pointer, field, rule, file, diagnostics);
}

#[derive(Clone, Copy)]
pub(super) struct IntegerListRule {
    range: (i64, i64),
    allow_string_values: bool,
    allow_scalar: bool,
}

fn validate_schedule_integer_value(
    entry: &json_spanned_value::spanned::Value,
    pointer: &str,
    field: &str,
    rule: IntegerListRule,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if is_opaque_arm_expression(file, entry) {
        return;
    }
    if let Some(text) = as_string(entry)
        && (wdl_string_is_full_expression(text)
            || (rule.allow_string_values && wdl_string_may_be_integer(text)))
    {
        return;
    }
    let number = if rule.allow_string_values {
        integer_or_integer_string_value(entry)
    } else {
        integer_value(entry)
    };
    let Some(number) = number else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer.to_owned(),
            Some(span(entry)),
            if rule.allow_string_values {
                format!("Recurrence schedule.{field} entries must be integers or integer strings")
            } else {
                format!("Recurrence schedule.{field} entries must be integers")
            },
        ));
        return;
    };
    // `monthDays` uses 1..=31 and -31..=-1 (from end of month); zero is not
    // a valid month day in either direction.
    if number < rule.range.0 || number > rule.range.1 || (field == "monthDays" && number == 0) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer.to_owned(),
            Some(span(entry)),
            format!("Recurrence schedule.{field} value {number} is out of range"),
        ));
    }
}

/// Validate `schedule.monthlyOccurrences`: an array of
/// `{ occurrence, dayOfWeek }`. Encodes "the Nth <weekday> of the month",
/// where `occurrence` runs -5..=-1 (from end) or 1..=5.
pub(super) fn validate_monthly_occurrences(
    schedule: &json_spanned_value::spanned::Value,
    schedule_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(monthly_occurrences) = get(schedule, "monthlyOccurrences") else {
        return;
    };
    if arm_optional_property_absent(file, monthly_occurrences)
        || is_opaque_arm_expression(file, monthly_occurrences)
    {
        return;
    }
    let monthly_pointer = pointer_join(schedule_pointer, "monthlyOccurrences");
    let Some(values) = monthly_occurrences.as_span_array() else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            monthly_pointer,
            Some(span(monthly_occurrences)),
            "Recurrence schedule.monthlyOccurrences must be an array",
        ));
        return;
    };
    for (index, occurrence) in values.iter().enumerate() {
        let occurrence_pointer = pointer_join(&monthly_pointer, &index.to_string());
        if is_opaque_arm_expression(file, occurrence) {
            continue;
        }
        if as_object(occurrence).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                occurrence_pointer,
                Some(span(occurrence)),
                "Recurrence schedule.monthlyOccurrences entries must be objects",
            ));
            continue;
        }
        validate_monthly_occurrence_number(occurrence, &occurrence_pointer, file, diagnostics);
        validate_required_string_enum(
            occurrence,
            &occurrence_pointer,
            "dayOfWeek",
            "Recurrence schedule.monthlyOccurrences.dayOfWeek",
            RECURRENCE_WEEK_DAYS,
            file,
            diagnostics,
        );
    }
}

/// Validate the `occurrence` integer of a monthlyOccurrence entry: required,
/// non-zero, and within -5..=5.
pub(super) fn validate_monthly_occurrence_number(
    occurrence: &json_spanned_value::spanned::Value,
    occurrence_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(occurrence, "occurrence") else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(occurrence_pointer, "occurrence"),
            Some(span(occurrence)),
            "object is missing required field 'occurrence'",
        ));
        return;
    };
    if is_opaque_arm_expression(file, value) {
        return;
    }
    let Some(number) = integer_value(value) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(occurrence_pointer, "occurrence"),
            Some(span(value)),
            "Recurrence schedule.monthlyOccurrences.occurrence must be an integer",
        ));
        return;
    };
    if !(-5..=5).contains(&number) || number == 0 {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(occurrence_pointer, "occurrence"),
            Some(span(value)),
            format!(
                "Recurrence schedule.monthlyOccurrences.occurrence value {number} is out of range"
            ),
        ));
    }
}
