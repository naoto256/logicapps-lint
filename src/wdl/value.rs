//! Structural classification of a JSON string as a WDL value.
//!
//! Per-rule shape checks (`equals`, `startsWith`, character-length limits,
//! etc.) need to know how much of a string is statically known. This module
//! folds a raw JSON string into one of four cases and exposes the static
//! fragments that survive dynamic interpolation, without ever evaluating
//! the expression.

use std::borrow::Cow;

/// Classification of a JSON string with respect to WDL dynamic content.
///
/// `Literal` — no expression at all, possibly with `@@` escapes unfolded.
/// `FullExpression` — the whole string is a single root expression; its
/// value is entirely opaque to us.
/// `Template` — one or more `@{...}` interpolations spliced between known
/// literal segments.
/// `MalformedTemplate` — an `@{...}` opener without a matching close; we
/// keep it as "dynamic but opaque" so downstream rules do not silently
/// accept the malformed value as a literal match.
#[derive(Debug)]
pub(crate) enum WdlStringValue<'a> {
    Literal(Cow<'a, str>),
    FullExpression,
    Template(WdlStringTemplate),
    MalformedTemplate,
}

/// Literal fragments of a template value in source order.
///
/// A template with N interpolations produces exactly N+1 literal segments;
/// the first is the prefix before the first `@{...}`, the last is the
/// suffix after the final `@{...}`, and each internal segment is the text
/// between adjacent interpolations. Segments may be empty (e.g. two
/// interpolations back-to-back), but the count invariant is what powers the
/// pattern-matching helpers below.
#[derive(Debug)]
pub(crate) struct WdlStringTemplate {
    literal_segments: Vec<String>,
}

impl<'a> WdlStringValue<'a> {
    /// Classify a raw JSON string value into one of the four WDL cases.
    ///
    /// Fast path: strings without any `@` byte are literal by definition and
    /// are returned as a borrowed `Cow` to avoid allocation.
    pub(crate) fn classify(value: &'a str) -> Self {
        if !value.as_bytes().contains(&b'@') {
            return Self::Literal(Cow::Borrowed(value));
        }
        if value.starts_with('@') && !value.starts_with("@@") && !value.starts_with("@{") {
            return Self::FullExpression;
        }

        match parse_template(value) {
            Ok(ParsedTemplate::Literal(None)) => Self::Literal(Cow::Borrowed(value)),
            Ok(ParsedTemplate::Literal(Some(value))) => Self::Literal(Cow::Owned(value)),
            Ok(ParsedTemplate::Template(literal_segments)) => {
                Self::Template(WdlStringTemplate { literal_segments })
            }
            Err(()) => Self::MalformedTemplate,
        }
    }

    /// True when the runtime value depends on evaluated content.
    /// `MalformedTemplate` is treated as dynamic on purpose: we cannot claim
    /// a broken interpolation is a static literal.
    pub(crate) fn has_dynamic_value(&self) -> bool {
        matches!(
            self,
            Self::FullExpression | Self::Template(_) | Self::MalformedTemplate
        )
    }

    /// True only for root-form expressions where the entire string is opaque.
    pub(crate) fn is_full_expression(&self) -> bool {
        matches!(self, Self::FullExpression)
    }

    /// Return the underlying literal text, or `None` if any part is dynamic.
    pub(crate) fn literal(&self) -> Option<&str> {
        match self {
            Self::Literal(value) => Some(value.as_ref()),
            Self::FullExpression | Self::Template(_) | Self::MalformedTemplate => None,
        }
    }

    /// Return the template shape when the value is a well-formed template.
    pub(crate) fn template(&self) -> Option<&WdlStringTemplate> {
        match self {
            Self::Template(template) => Some(template),
            Self::Literal(_) | Self::FullExpression | Self::MalformedTemplate => None,
        }
    }

    /// Conservative "could this value equal one of `allowed`?" query.
    /// Dynamic values return `true` because we cannot rule the match out;
    /// this keeps rules from firing false positives on runtime-computed
    /// strings that a human reviewer would consider valid.
    pub(crate) fn may_match_exact(&self, allowed: &[&str]) -> bool {
        match self {
            Self::Literal(value) => allowed.contains(&value.as_ref()),
            Self::FullExpression | Self::MalformedTemplate => true,
            Self::Template(template) => allowed
                .iter()
                .any(|candidate| template.may_match_exact(candidate)),
        }
    }

    /// Same as `may_match_exact` but with ASCII case folding. Non-ASCII
    /// bytes are compared byte-for-byte since Logic Apps identifiers and
    /// enum-like values are ASCII in practice.
    pub(crate) fn may_match_exact_ignore_case(&self, allowed: &[&str]) -> bool {
        match self {
            Self::Literal(value) => allowed
                .iter()
                .any(|candidate| value.eq_ignore_ascii_case(candidate)),
            Self::FullExpression | Self::MalformedTemplate => true,
            Self::Template(template) => allowed
                .iter()
                .any(|candidate| template.may_match_exact_ignore_case(candidate)),
        }
    }

    /// Conservative "could this value have exactly `expected` characters?"
    /// Templates return true whenever their static text alone does not
    /// already exceed the limit — an interpolation could contribute the
    /// remainder. Character count is Unicode-scalar based to match how
    /// downstream length rules are specified.
    pub(crate) fn may_have_char_len(&self, expected: usize) -> bool {
        match self {
            Self::Literal(value) => value.chars().count() == expected,
            Self::FullExpression | Self::MalformedTemplate => true,
            Self::Template(template) => template.minimum_char_len() <= expected,
        }
    }
}

impl WdlStringTemplate {
    /// Borrow the full segment list. The vector is never empty for a
    /// well-formed template.
    pub(crate) fn literal_segments(&self) -> &[String] {
        &self.literal_segments
    }

    /// Static text before the first interpolation. Used by prefix-based
    /// rules such as `startsWith`.
    pub(crate) fn static_prefix(&self) -> &str {
        self.literal_segments
            .first()
            .map(String::as_str)
            .unwrap_or_default()
    }

    /// Static text after the final interpolation. Used by suffix-based
    /// rules such as `endsWith`.
    pub(crate) fn static_suffix(&self) -> &str {
        self.literal_segments
            .last()
            .map(String::as_str)
            .unwrap_or_default()
    }

    /// Sum of the byte lengths of every literal segment. Since each
    /// interpolation contributes at least zero bytes, this is a safe lower
    /// bound on the runtime byte length.
    pub(crate) fn minimum_len(&self) -> usize {
        self.literal_segments
            .iter()
            .map(|segment| segment.len())
            .sum()
    }

    fn minimum_char_len(&self) -> usize {
        self.literal_segments
            .iter()
            .map(|segment| segment.chars().count())
            .sum()
    }

    /// True when every byte of every literal segment satisfies `predicate`.
    /// Interpolation output is not considered; callers use this for rules
    /// that gate on statically visible characters (e.g. a URL prefix that
    /// must not contain whitespace).
    pub(crate) fn literal_bytes_all(&self, predicate: impl Fn(u8) -> bool) -> bool {
        self.literal_segments
            .iter()
            .flat_map(|segment| segment.bytes())
            .all(predicate)
    }

    fn may_match_exact(&self, candidate: &str) -> bool {
        literal_segments_may_match(&self.literal_segments, candidate)
    }

    fn may_match_exact_ignore_case(&self, candidate: &str) -> bool {
        let segments = self
            .literal_segments
            .iter()
            .map(|segment| segment.to_ascii_lowercase())
            .collect::<Vec<_>>();
        literal_segments_may_match(&segments, &candidate.to_ascii_lowercase())
    }
}

enum ParsedTemplate {
    Literal(Option<String>),
    Template(Vec<String>),
}

/// Walk `value` splitting it into literal segments interleaved with
/// interpolation placeholders. `@@` collapses to a literal `@`; `@{...}`
/// pushes the accumulated literal onto the segment list and skips past the
/// interpolation body. An unterminated `@{...}` is reported as `Err(())`
/// which callers surface as `MalformedTemplate`.
fn parse_template(value: &str) -> Result<ParsedTemplate, ()> {
    let bytes = value.as_bytes();
    let mut segments = Vec::new();
    let mut literal = String::new();
    let mut index = 0;
    let mut saw_escape = false;
    let mut saw_interpolation = false;
    while index < bytes.len() {
        if bytes[index] == b'@' && bytes.get(index + 1) == Some(&b'@') {
            literal.push('@');
            saw_escape = true;
            index += 2;
            continue;
        }
        if bytes[index] == b'@' && bytes.get(index + 1) == Some(&b'{') {
            let close = interpolation_close(value, index + 2).ok_or(())?;
            segments.push(std::mem::take(&mut literal));
            saw_interpolation = true;
            index = close + 1;
            continue;
        }
        let character = value[index..].chars().next().ok_or(())?;
        literal.push(character);
        index += character.len_utf8();
    }
    if saw_interpolation {
        segments.push(literal);
        Ok(ParsedTemplate::Template(segments))
    } else if saw_escape {
        Ok(ParsedTemplate::Literal(Some(literal)))
    } else {
        Ok(ParsedTemplate::Literal(None))
    }
}

/// Find the `}` that closes the interpolation whose body starts at
/// `expression_start`. Braces inside single-quoted string literals do not
/// count; doubled quotes (`''`) are the WDL escape and do not toggle the
/// in-string flag.
fn interpolation_close(value: &str, expression_start: usize) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut index = expression_start;
    let mut in_string = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' => {
                if in_string && bytes.get(index + 1) == Some(&b'\'') {
                    index += 2;
                    continue;
                }
                in_string = !in_string;
            }
            b'}' if !in_string => return Some(index),
            _ => {}
        }
        index += 1;
    }
    None
}

/// Check whether `candidate` can be produced by the template whose static
/// pieces are `segments`, treating each gap between adjacent segments as a
/// wildcard filled by an interpolation. The first segment must be a
/// prefix, the last must be a suffix, and each interior segment must
/// appear in order without overlap.
fn literal_segments_may_match(segments: &[String], candidate: &str) -> bool {
    let Some(first) = segments.first() else {
        return true;
    };
    if !candidate.starts_with(first.as_str()) {
        return false;
    }
    let mut offset = first.len();
    for (index, segment) in segments.iter().enumerate().skip(1) {
        if segment.is_empty() {
            continue;
        }
        let Some(relative) = candidate[offset..].find(segment.as_str()) else {
            return false;
        };
        offset += relative + segment.len();
        if index == segments.len() - 1 && !candidate.ends_with(segment.as_str()) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_full_expression_and_interpolation_separately() {
        assert!(WdlStringValue::classify("@concat('a', 'b')").is_full_expression());
        let value = WdlStringValue::classify("@{concat('a', 'b')}");
        let template = value.template().expect("interpolation template");
        assert_eq!(template.literal_segments(), &[String::new(), String::new()]);
    }

    #[test]
    fn exact_matching_uses_static_template_suffixes() {
        let value = WdlStringValue::classify("@{parameters('prefix')}Bogus");
        assert!(!value.may_match_exact(&["Second", "Minute"]));
        let value = WdlStringValue::classify("@{parameters('prefix')}cond");
        assert!(value.may_match_exact(&["Second"]));
    }

    #[test]
    fn leading_at_escape_is_a_literal_value() {
        let value = WdlStringValue::classify("@@");
        assert_eq!(value.literal(), Some("@"));
    }

    #[test]
    fn leading_at_escape_keeps_later_interpolation_dynamic() {
        let value = WdlStringValue::classify("@@prefix @{parameters('suffix')}");
        let template = value.template().expect("interpolation template");
        assert_eq!(template.static_prefix(), "@prefix ");
        assert_eq!(template.static_suffix(), "");

        let value = WdlStringValue::classify("@@@{parameters('suffix')}");
        let template = value.template().expect("interpolation template");
        assert_eq!(template.static_prefix(), "@");
    }

    #[test]
    fn malformed_interpolation_remains_dynamic_but_opaque() {
        let value = WdlStringValue::classify("prefix @{parameters('suffix')");
        assert!(value.has_dynamic_value());
        assert!(value.template().is_none());
    }
}
