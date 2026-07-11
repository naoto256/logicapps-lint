//! ARM / WDL boundary helpers.
//!
//! A string reaching the reference checker can be authored WDL, authored ARM,
//! or a fragment materialized by static ARM evaluation. WDL syntax is only
//! meaningful for strings whose runtime shape is WDL; ARM literals may just
//! be payload text that happens to contain `@`.

/// Whether the entire string is a single ARM template expression (`[...]`),
/// in which case the WDL layer must not touch it.
pub(super) fn is_arm_template_expression(text: &str) -> bool {
    crate::arm::is_full_expression(text)
}

/// Decide whether an ARM-materialized fragment is worth handing to the WDL
/// syntax checker. A partial ARM literal is only interesting if it actually
/// looks like WDL: a balanced `@{...}` interpolation, or a bare `@name(...)`
/// call. Otherwise it is treated as opaque payload text.
pub(super) fn arm_static_wdl_syntax_check(text: &str, can_extend_right: bool) -> bool {
    // `@{...}` counts as WDL if the closing brace is present, or if the
    // fragment cannot grow further right (so the missing `}` is a real error).
    text.contains("@{") && (text.contains('}') || !can_extend_right)
        || contains_unbraced_wdl_call(text)
}

/// Detect a bare `@identifier(...)` call not wrapped in `@{...}`. Requires a
/// following `(` and closing `)` so we don't misfire on stray `@` characters
/// in payload text (emails, decorators, etc.).
fn contains_unbraced_wdl_call(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'@'
            && bytes[index + 1] != b'{'
            && bytes[index + 1] != b'@'
            && bytes[index + 1].is_ascii_alphabetic()
            && text[index + 1..]
                .find('(')
                .is_some_and(|open| text[index + 1 + open..].contains(')'))
        {
            return true;
        }
        index += 1;
    }
    false
}
