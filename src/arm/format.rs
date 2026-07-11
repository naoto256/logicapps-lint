//! Implementation of ARM `format(...)`.
//!
//! Mirrors a subset of .NET composite formatting: `{index[,alignment][:spec]}`.
//! Doubled braces `{{` / `}}` are literal `{` / `}`. Only two format specifiers
//! are honored: `d`/`D` (zero-padded decimal integer) and `n`/`N` (grouped
//! number with optional precision) — everything else falls back to the raw
//! replacement string.

use super::StaticStringFragment;

/// One replacement slot for the fragment variant of `format`. When `value` is
/// `None` the replacement is opaque and the surrounding format literal is
/// split at that slot. `can_extend_to_wdl_escape` indicates the opaque runtime
/// value could begin with `@` and so may synthesise a WDL escape at the seam.
pub(super) struct FormatFragmentReplacement {
    pub(super) value: Option<String>,
    pub(super) can_extend_to_wdl_escape: bool,
}

/// Fully materialize `format(value, replacements...)` when every replacement
/// is available. Returns `None` if an out-of-range slot is referenced.
pub(super) fn format_literal(value: &str, replacements: &[String]) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '{' && chars.peek() == Some(&'{') {
            chars.next();
            out.push('{');
        } else if ch == '}' && chars.peek() == Some(&'}') {
            chars.next();
            out.push('}');
        } else if ch == '{' {
            let Some((index, format_spec)) = format_placeholder(&mut chars) else {
                out.push('{');
                continue;
            };
            out.push_str(&format_replacement(replacements.get(index)?, format_spec));
        } else if ch == '}' {
            out.push('}');
        } else {
            out.push(ch);
        }
    }
    Some(out)
}

/// Fragment variant used when some `format` replacements are opaque.
///
/// Emits a sequence of [`StaticStringFragment`]s: contiguous literal text
/// (with fully-resolved replacements substituted in place) becomes one
/// fragment; each opaque replacement acts as a splitter and updates the
/// left/right extension flags on the neighbouring fragments so callers can
/// tell where an opaque value could bleed into text.
pub(super) fn format_literal_fragments(
    value: &str,
    replacements: &[FormatFragmentReplacement],
) -> Option<Vec<StaticStringFragment>> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut current_can_extend_left = false;
    let mut next_can_extend_left = false;
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '{' && chars.peek() == Some(&'{') {
            chars.next();
            if current.is_empty() {
                current_can_extend_left = next_can_extend_left;
            }
            next_can_extend_left = false;
            current.push('{');
        } else if ch == '}' && chars.peek() == Some(&'}') {
            chars.next();
            if current.is_empty() {
                current_can_extend_left = next_can_extend_left;
            }
            next_can_extend_left = false;
            current.push('}');
        } else if ch == '{' {
            let Some((index, format_spec)) = format_placeholder(&mut chars) else {
                current.push('{');
                continue;
            };
            match replacements.get(index)? {
                FormatFragmentReplacement {
                    value: Some(replacement),
                    ..
                } => {
                    if current.is_empty() {
                        current_can_extend_left = next_can_extend_left;
                    }
                    next_can_extend_left = false;
                    current.push_str(&format_replacement(replacement, format_spec));
                }
                FormatFragmentReplacement {
                    value: None,
                    can_extend_to_wdl_escape,
                } => {
                    if !current.is_empty() {
                        out.push(StaticStringFragment {
                            value: std::mem::take(&mut current),
                            can_extend_left: current_can_extend_left,
                            can_extend_right: true,
                        });
                        current_can_extend_left = false;
                    }
                    next_can_extend_left = *can_extend_to_wdl_escape;
                }
            }
        } else if ch == '}' {
            if current.is_empty() {
                current_can_extend_left = next_can_extend_left;
            }
            next_can_extend_left = false;
            current.push('}');
        } else {
            if current.is_empty() {
                current_can_extend_left = next_can_extend_left;
            }
            next_can_extend_left = false;
            current.push(ch);
        }
    }
    if !current.is_empty() {
        out.push(StaticStringFragment {
            value: current,
            can_extend_left: current_can_extend_left,
            can_extend_right: false,
        });
    }
    Some(out)
}

// Parse a single `{index[,alignment][:spec]}` placeholder. Cursor is expected
// to be positioned just after the opening `{`. Returns the parsed index and
// optional format spec; consumes through the closing `}`. Alignment is
// syntactically accepted and discarded (padding is not honored).
fn format_placeholder(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Option<(usize, Option<String>)> {
    if !chars.peek().is_some_and(char::is_ascii_digit) {
        return None;
    }
    let mut index = String::new();
    while let Some(next) = chars.peek() {
        if next.is_ascii_digit() {
            index.push(*next);
            chars.next();
        } else {
            break;
        }
    }
    while chars.peek().is_some_and(|next| next.is_whitespace()) {
        chars.next();
    }
    if chars.peek() == Some(&',') {
        chars.next();
        while chars.peek().is_some_and(|next| next.is_whitespace()) {
            chars.next();
        }
        if chars.peek().is_some_and(|next| matches!(next, '+' | '-')) {
            chars.next();
        }
        while chars.peek().is_some_and(char::is_ascii_digit) {
            chars.next();
        }
        while chars.peek().is_some_and(|next| next.is_whitespace()) {
            chars.next();
        }
    }
    let mut format_spec = None;
    if chars.peek() == Some(&':') {
        chars.next();
        let mut spec = String::new();
        while let Some(next) = chars.peek() {
            if *next == '}' {
                break;
            }
            spec.push(*next);
            chars.next();
        }
        format_spec = Some(spec);
    }
    if chars.next() != Some('}') {
        return None;
    }
    Some((index.parse::<usize>().ok()?, format_spec))
}

// Apply the (already-parsed) format specifier to a replacement string.
// Unknown specifiers fall back to the raw replacement so we never lose data.
fn format_replacement(value: &str, format_spec: Option<String>) -> String {
    let Some(format_spec) = format_spec else {
        return value.to_owned();
    };
    let mut chars = format_spec.chars();
    let Some(kind) = chars.next() else {
        return value.to_owned();
    };
    match kind {
        'd' | 'D' => format_decimal_integer(value, chars.as_str()),
        'n' | 'N' => format_number_with_grouping(value, chars.as_str()),
        _ => None,
    }
    .unwrap_or_else(|| value.to_owned())
}

fn format_decimal_integer(value: &str, width_text: &str) -> Option<String> {
    if !width_text.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let width = width_text.parse::<usize>().ok()?;
    let number = value.parse::<i64>().ok()?;
    Some(if number < 0 {
        format!("-{:0width$}", number.abs())
    } else {
        format!("{number:0width$}")
    })
}

// `n`/`N` specifier: thousands-separated number with fixed fractional digits.
// Default precision is 2, matching .NET. `n0` on integers is routed through
// i128 to preserve range; anything else goes through f64.
fn format_number_with_grouping(value: &str, precision_text: &str) -> Option<String> {
    if !precision_text.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let precision = if precision_text.is_empty() {
        2
    } else {
        precision_text.parse::<usize>().ok()?
    };
    if precision == 0
        && let Ok(number) = value.parse::<i128>()
    {
        let sign = if number < 0 { "-" } else { "" };
        let digits = grouped_decimal_digits(&number.abs().to_string());
        return Some(format!("{sign}{digits}"));
    }
    let number = value.parse::<f64>().ok()?;
    if !number.is_finite() {
        return None;
    }
    let sign = if number.is_sign_negative() { "-" } else { "" };
    let formatted = format!("{:.*}", precision, number.abs());
    let (integer, fraction) = formatted.split_once('.').unwrap_or((&formatted, ""));
    let mut out = format!("{sign}{}", grouped_decimal_digits(integer));
    if precision > 0 {
        out.push('.');
        out.push_str(fraction);
    }
    Some(out)
}

fn grouped_decimal_digits(digits: &str) -> String {
    let mut out = String::new();
    for (index, ch) in digits.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}
