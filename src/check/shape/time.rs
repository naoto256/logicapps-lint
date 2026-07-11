//! Time-shaped predicates: ISO 8601 durations, ISO 8601 datetimes, and the
//! Windows time-zone id enum used by `Recurrence` triggers and delay actions.
//!
//! Retry policies, request timeouts, delay windows — every duration field in
//! Logic Apps is an ISO 8601 duration (`PT1S`, `P1D`, …). Datetimes flow
//! through `startTime` on scheduled triggers. The enum below matches the
//! Windows time-zone table the runtime resolves against; both variants (`Z`
//! suffix and explicit UTC offset) are accepted for datetimes.

pub(super) const TIME_UNITS: &[&str] =
    &["Day", "Hour", "Minute", "Month", "Second", "Week", "Year"];

const WINDOWS_TIME_ZONES: &[&str] = &[
    "Afghanistan Standard Time",
    "Alaskan Standard Time",
    "Aleutian Standard Time",
    "Altai Standard Time",
    "Arab Standard Time",
    "Arabian Standard Time",
    "Arabic Standard Time",
    "Argentina Standard Time",
    "Astrakhan Standard Time",
    "Atlantic Standard Time",
    "AUS Central Standard Time",
    "AUS Eastern Standard Time",
    "Aus Central W. Standard Time",
    "Azerbaijan Standard Time",
    "Azores Standard Time",
    "Bahia Standard Time",
    "Bangladesh Standard Time",
    "Belarus Standard Time",
    "Bougainville Standard Time",
    "Canada Central Standard Time",
    "Cape Verde Standard Time",
    "Caucasus Standard Time",
    "Cen. Australia Standard Time",
    "Central America Standard Time",
    "Central Asia Standard Time",
    "Central Brazilian Standard Time",
    "Central Europe Standard Time",
    "Central European Standard Time",
    "Central Pacific Standard Time",
    "Central Standard Time",
    "Central Standard Time (Mexico)",
    "Chatham Islands Standard Time",
    "China Standard Time",
    "Cuba Standard Time",
    "Dateline Standard Time",
    "E. Africa Standard Time",
    "E. Australia Standard Time",
    "E. Europe Standard Time",
    "E. South America Standard Time",
    "Easter Island Standard Time",
    "Eastern Standard Time",
    "Eastern Standard Time (Mexico)",
    "Egypt Standard Time",
    "Ekaterinburg Standard Time",
    "Fiji Standard Time",
    "FLE Standard Time",
    "Georgian Standard Time",
    "GMT Standard Time",
    "Greenland Standard Time",
    "Greenwich Standard Time",
    "GTB Standard Time",
    "Haiti Standard Time",
    "Hawaiian Standard Time",
    "India Standard Time",
    "Iran Standard Time",
    "Israel Standard Time",
    "Jordan Standard Time",
    "Kaliningrad Standard Time",
    "Kamchatka Standard Time",
    "Korea Standard Time",
    "Libya Standard Time",
    "Line Islands Standard Time",
    "Lord Howe Standard Time",
    "Magadan Standard Time",
    "Marquesas Standard Time",
    "Mauritius Standard Time",
    "Middle East Standard Time",
    "Montevideo Standard Time",
    "Morocco Standard Time",
    "Mountain Standard Time",
    "Mountain Standard Time (Mexico)",
    "Myanmar Standard Time",
    "N. Central Asia Standard Time",
    "Namibia Standard Time",
    "Nepal Standard Time",
    "New Zealand Standard Time",
    "Newfoundland Standard Time",
    "Norfolk Standard Time",
    "North Asia East Standard Time",
    "North Asia Standard Time",
    "North Korea Standard Time",
    "Omsk Standard Time",
    "Pacific SA Standard Time",
    "Pacific Standard Time",
    "Pacific Standard Time (Mexico)",
    "Pakistan Standard Time",
    "Paraguay Standard Time",
    "Qyzylorda Standard Time",
    "Romance Standard Time",
    "Russia Time Zone 10",
    "Russia Time Zone 11",
    "Russia Time Zone 3",
    "Russian Standard Time",
    "SA Eastern Standard Time",
    "SA Pacific Standard Time",
    "SA Western Standard Time",
    "Saint Pierre Standard Time",
    "Sakhalin Standard Time",
    "Samoa Standard Time",
    "Sao Tome Standard Time",
    "Saratov Standard Time",
    "SE Asia Standard Time",
    "Singapore Standard Time",
    "South Africa Standard Time",
    "South Sudan Standard Time",
    "Sri Lanka Standard Time",
    "Sudan Standard Time",
    "Syria Standard Time",
    "Taipei Standard Time",
    "Tasmania Standard Time",
    "Tocantins Standard Time",
    "Tokyo Standard Time",
    "Tomsk Standard Time",
    "Tonga Standard Time",
    "Transbaikal Standard Time",
    "Turkey Standard Time",
    "Turks And Caicos Standard Time",
    "Ulaanbaatar Standard Time",
    "US Eastern Standard Time",
    "US Mountain Standard Time",
    "UTC",
    "UTC+12",
    "UTC+13",
    "UTC-02",
    "UTC-08",
    "UTC-09",
    "UTC-11",
    "Venezuela Standard Time",
    "Vladivostok Standard Time",
    "W. Australia Standard Time",
    "W. Central Africa Standard Time",
    "W. Europe Standard Time",
    "W. Mongolia Standard Time",
    "West Asia Standard Time",
    "West Bank Standard Time",
    "West Pacific Standard Time",
    "Yakutsk Standard Time",
    "Yukon Standard Time",
];

/// Strict ISO 8601 duration parser.
///
/// Requires the leading `P`, at least one component, `T` before hour/minute/
/// second units, and rejects mixed date/time unit order. Fractional components
/// are accepted with either `.` or `,` as the decimal mark.
pub(super) fn is_iso8601_duration(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('P') else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }

    let mut has_component = false;
    let mut in_time = false;
    let mut chars = rest.chars().peekable();
    while let Some(ch) = chars.peek().copied() {
        if ch == 'T' {
            if in_time {
                return false;
            }
            in_time = true;
            chars.next();
            continue;
        }

        let mut saw_digit = false;
        while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
            saw_digit = true;
            chars.next();
        }
        if chars.peek() == Some(&'.') || chars.peek() == Some(&',') {
            chars.next();
            let mut fractional_digit = false;
            while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
                fractional_digit = true;
                chars.next();
            }
            saw_digit &= fractional_digit;
        }
        if !saw_digit {
            return false;
        }

        let Some(unit) = chars.next() else {
            return false;
        };
        let valid_unit = if in_time {
            matches!(unit, 'H' | 'M' | 'S')
        } else {
            matches!(unit, 'Y' | 'M' | 'W' | 'D')
        };
        if !valid_unit {
            return false;
        }
        has_component = true;
    }

    has_component
}

/// Strict ISO 8601 datetime parser: `YYYY-MM-DDTHH:MM:SS`, optional fractional
/// seconds, optional `Z` or `±HH:MM` offset. Month/day validity is enforced,
/// including leap years.
pub(super) fn is_iso8601_datetime(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 19 {
        return false;
    }
    if !ascii_digits(bytes, 0, 4)
        || bytes.get(4) != Some(&b'-')
        || !ascii_digits(bytes, 5, 2)
        || bytes.get(7) != Some(&b'-')
        || !ascii_digits(bytes, 8, 2)
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || !ascii_digits(bytes, 11, 2)
        || bytes.get(13) != Some(&b':')
        || !ascii_digits(bytes, 14, 2)
        || bytes.get(16) != Some(&b':')
        || !ascii_digits(bytes, 17, 2)
    {
        return false;
    }
    if !valid_iso8601_datetime_components(bytes) {
        return false;
    }

    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    if index == bytes.len() {
        return true;
    }
    if matches!(bytes.get(index), Some(b'Z' | b'z')) {
        return index + 1 == bytes.len();
    }
    if matches!(bytes.get(index), Some(b'+' | b'-')) {
        return bytes.len() == index + 6
            && ascii_digits(bytes, index + 1, 2)
            && bytes.get(index + 3) == Some(&b':')
            && ascii_digits(bytes, index + 4, 2);
    }
    false
}

/// Case-sensitive lookup against the Windows time-zone table shipped with the
/// runtime. IANA ids ("America/Los_Angeles") are *not* accepted.
pub(super) fn is_windows_time_zone(value: &str) -> bool {
    WINDOWS_TIME_ZONES.contains(&value)
}

/// True when the datetime carries an explicit UTC (`Z`) marker.
pub(super) fn iso8601_datetime_has_z_suffix(value: &str) -> bool {
    iso8601_datetime_timezone_start(value)
        .is_some_and(|index| matches!(value.as_bytes().get(index), Some(b'Z' | b'z')))
}

/// True when the datetime carries an explicit `+HH:MM` / `-HH:MM` offset.
pub(super) fn iso8601_datetime_has_utc_offset(value: &str) -> bool {
    iso8601_datetime_timezone_start(value)
        .is_some_and(|index| matches!(value.as_bytes().get(index), Some(b'+' | b'-')))
}

fn iso8601_datetime_timezone_start(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
    }
    matches!(bytes.get(index), Some(b'Z' | b'z' | b'+' | b'-')).then_some(index)
}

fn valid_iso8601_datetime_components(bytes: &[u8]) -> bool {
    let Some(year) = parse_ascii_u32(bytes, 0, 4) else {
        return false;
    };
    let Some(month) = parse_ascii_u32(bytes, 5, 2) else {
        return false;
    };
    let Some(day) = parse_ascii_u32(bytes, 8, 2) else {
        return false;
    };
    let Some(hour) = parse_ascii_u32(bytes, 11, 2) else {
        return false;
    };
    let Some(minute) = parse_ascii_u32(bytes, 14, 2) else {
        return false;
    };
    let Some(second) = parse_ascii_u32(bytes, 17, 2) else {
        return false;
    };
    (1..=12).contains(&month)
        && (1..=days_in_month(year, month)).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 59
}

fn parse_ascii_u32(bytes: &[u8], start: usize, len: usize) -> Option<u32> {
    let mut value = 0u32;
    for byte in bytes.get(start..start + len)? {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u32::from(byte - b'0');
    }
    Some(value)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn ascii_digits(bytes: &[u8], start: usize, len: usize) -> bool {
    bytes
        .get(start..start + len)
        .is_some_and(|digits| digits.iter().all(u8::is_ascii_digit))
}
