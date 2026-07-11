//! Date helpers for recurrence trigger validation. Self-contained civil-date
//! arithmetic (Howard Hinnant's algorithm) is used to avoid pulling in a
//! full calendar crate — we only need day-precision comparisons for the
//! future-limit check.

use super::super::*;
use std::time::{SystemTime, UNIX_EPOCH};

/// The Logic Apps scheduler rejects a `recurrence.startTime` more than 49
/// years in the future. We approximate today's UTC date and compare on the
/// calendar; sub-day precision is not required for this bound.
pub(super) fn validate_recurrence_start_time_future_limit(
    text: &str,
    recurrence_pointer: &str,
    value: &json_spanned_value::spanned::Value,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(start_date) = iso8601_date(text) else {
        return;
    };
    let Some(today) = current_utc_date() else {
        return;
    };
    if date_after(start_date, add_years(today, 49)) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(recurrence_pointer, "startTime"),
            Some(span(value)),
            "Recurrence startTime must be at most 49 years in the future",
        ));
    }
}

fn iso8601_date(value: &str) -> Option<(i32, u32, u32)> {
    Some((
        value.get(0..4)?.parse().ok()?,
        value.get(5..7)?.parse().ok()?,
        value.get(8..10)?.parse().ok()?,
    ))
}

fn current_utc_date() -> Option<(i32, u32, u32)> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let days = i64::try_from(seconds / 86_400).ok()?;
    Some(civil_from_days(days))
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(month <= 2);
    (
        i32::try_from(year).unwrap_or(i32::MAX),
        u32::try_from(month).unwrap_or(12),
        u32::try_from(day).unwrap_or(31),
    )
}

fn add_years(date: (i32, u32, u32), years: i32) -> (i32, u32, u32) {
    let year = date.0.saturating_add(years);
    let month = date.1;
    let day = date.2.min(days_in_month(year, month));
    (year, month, day)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year(year) => 29,
        2 => 28,
        _ => 31,
    }
}

fn leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn date_after(left: (i32, u32, u32), right: (i32, u32, u32)) -> bool {
    left > right
}

#[cfg(test)]
mod recurrence_date_tests {
    use super::{add_years, civil_from_days};

    #[test]
    fn unix_epoch_date_conversion_is_stable() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_273), (2025, 7, 4));
    }

    #[test]
    fn add_years_clamps_leap_day() {
        assert_eq!(add_years((2024, 2, 29), 1), (2025, 2, 28));
    }
}
