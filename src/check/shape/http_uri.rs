//! URI shape checks for HTTP endpoints and generic URI fields.
//!
//! WDL string interpolation is legal anywhere a URI appears, so the rules
//! evaluate whatever literal portion is knowable: for HTTP endpoints, the
//! scheme prefix must be compatible with `http` / `https` and the length must
//! stay within the runtime's 2048-byte cap; for generic URIs the whole string
//! is parsed as RFC 3986. Interpolated segments are assumed to be well-formed
//! until proven otherwise.

use super::materialized::arm_optional_property_absent;
use super::*;

/// Validate an HTTP(S) endpoint URI, enforcing the runtime's 2048-byte cap.
pub(super) fn validate_http_endpoint_uri(
    object: &json_spanned_value::spanned::Value,
    object_pointer: &str,
    field: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(object, field) else {
        return;
    };
    if arm_optional_property_absent(file, value) || is_opaque_arm_expression(file, value) {
        return;
    }
    let Some(text) = as_string(value) else {
        return;
    };
    let analyzed = crate::wdl::WdlStringValue::classify(text);
    // Template path: validate the static prefix / suffix only, and use
    // `minimum_len` to enforce the byte cap even when interpolations are opaque.
    if let Some(template) = analyzed.template() {
        let pointer = pointer_join(object_pointer, field);
        if !valid_dynamic_http_endpoint_uri(template) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                pointer,
                Some(span(value)),
                format!("{label} must be an HTTP or HTTPS URL"),
            ));
        } else if template.minimum_len() > 2048 {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                pointer,
                Some(span(value)),
                format!("{label} must be at most 2048 bytes"),
            ));
        }
        return;
    }
    let Some(text) = analyzed.literal() else {
        return;
    };
    let pointer = pointer_join(object_pointer, field);
    if !valid_http_endpoint_uri(text) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer,
            Some(span(value)),
            format!("{label} must be an HTTP or HTTPS URL"),
        ));
        return;
    }
    if text.len() > 2048 {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer,
            Some(span(value)),
            format!("{label} must be at most 2048 bytes"),
        ));
    }
}

/// Validate a generic URI field (RFC 3986). Dynamic WDL strings are accepted
/// because the runtime resolves them before any URI parse would apply.
pub(super) fn validate_uri(
    object: &json_spanned_value::spanned::Value,
    object_pointer: &str,
    field: &str,
    label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = get(object, field) else {
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
    if !valid_uri(text) {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(object_pointer, field),
            Some(span(value)),
            format!("{label} must be a URI"),
        ));
    }
}

fn valid_uri(text: &str) -> bool {
    if has_invalid_uri_byte(text) {
        return false;
    }
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    let mut scheme_bytes = scheme.bytes();
    if !scheme_bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic())
        || !scheme_bytes.all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
    {
        return false;
    }
    let (hierarchy_and_query, fragment) = match rest.split_once('#') {
        Some((value, fragment)) if !fragment.contains('#') => (value, Some(fragment)),
        Some(_) => return false,
        None => (rest, None),
    };
    if fragment.is_some_and(|fragment| !valid_query_or_fragment(fragment)) {
        return false;
    }
    let (hierarchy, query) = match hierarchy_and_query.split_once('?') {
        Some((hierarchy, query)) => (hierarchy, Some(query)),
        None => (hierarchy_and_query, None),
    };
    if query.is_some_and(|query| !valid_query_or_fragment(query)) {
        return false;
    }
    let Some(authority_and_path) = hierarchy.strip_prefix("//") else {
        return valid_path(hierarchy);
    };
    let (authority, path) = match authority_and_path.split_once('/') {
        Some((authority, path)) => (authority, Some(path)),
        None => (authority_and_path, None),
    };
    if authority.is_empty() {
        return scheme.eq_ignore_ascii_case("file") && path.is_some_and(valid_path);
    }
    valid_uri_authority(authority) && path.is_none_or(valid_path)
}

fn valid_http_endpoint_uri(text: &str) -> bool {
    if has_invalid_uri_byte(text) {
        return false;
    }
    let Some((scheme, rest)) = text.split_once("://") else {
        return false;
    };
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !authority.is_empty() && valid_uri_authority(authority)
}

fn has_invalid_uri_byte(text: &str) -> bool {
    text.bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn valid_uri_authority(authority: &str) -> bool {
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (Some(userinfo), host_port),
        None => (None, authority),
    };
    if userinfo.is_some_and(|userinfo| {
        userinfo.contains('@') || !valid_encoded_component(userinfo, valid_userinfo_byte)
    }) {
        return false;
    }
    if let Some(host) = host_port.strip_prefix('[') {
        let Some((inside, suffix)) = host.split_once(']') else {
            return false;
        };
        return valid_ip_literal(inside) && valid_optional_port(suffix);
    }
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (host_port, None),
    };
    if host.contains(':') || host.is_empty() || !valid_reg_name(host) {
        return false;
    }
    port.is_none_or(valid_port)
}

fn valid_optional_port(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let Some(port) = value.strip_prefix(':') else {
        return false;
    };
    valid_port(port)
}

fn valid_port(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_ip_literal(value: &str) -> bool {
    value.parse::<std::net::Ipv6Addr>().is_ok() || valid_ipv_future(value)
}

fn valid_ipv_future(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('v').or_else(|| value.strip_prefix('V')) else {
        return false;
    };
    let Some((version, address)) = rest.split_once('.') else {
        return false;
    };
    !version.is_empty()
        && !address.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_hexdigit())
        && address.bytes().all(valid_ipv_future_address_byte)
}

fn valid_ipv_future_address_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:".contains(&byte)
}

fn valid_reg_name(value: &str) -> bool {
    valid_encoded_component(value, valid_reg_name_byte)
}

fn valid_path(value: &str) -> bool {
    valid_encoded_component(value, |byte| {
        byte == b'/' || valid_path_character_byte(byte)
    })
}

fn valid_query_or_fragment(value: &str) -> bool {
    valid_encoded_component(value, |byte| {
        matches!(byte, b'/' | b'?') || valid_path_character_byte(byte)
    })
}

fn valid_encoded_component(value: &str, valid_byte: impl Fn(u8) -> bool) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if valid_byte(byte) {
            index += 1;
            continue;
        }
        if byte == b'%'
            && bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
            && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            index += 3;
            continue;
        }
        return false;
    }
    true
}

fn valid_reg_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&byte)
}

fn valid_userinfo_byte(byte: u8) -> bool {
    valid_reg_name_byte(byte) || byte == b':'
}

fn valid_path_character_byte(byte: u8) -> bool {
    valid_userinfo_byte(byte) || byte == b'@'
}

/// Permissive template check. The static prefix must be a prefix of `http://`
/// or `https://` (or already contain the `://` separator with the right scheme);
/// literal segments must not contain control or whitespace characters.
fn valid_dynamic_http_endpoint_uri(template: &crate::wdl::WdlStringTemplate) -> bool {
    if template
        .literal_segments()
        .iter()
        .flat_map(|segment| segment.bytes())
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return false;
    }
    let prefix = template.static_prefix();
    if prefix.is_empty() {
        return true;
    }
    let Some((scheme, rest)) = prefix.split_once("://") else {
        // No scheme separator yet — an interpolation might still supply one, so
        // accept anything that is still a prefix of "http(s)://".
        let prefix = prefix.to_ascii_lowercase();
        return "http://".starts_with(&prefix) || "https://".starts_with(&prefix);
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return rest.is_empty();
    }
    if authority.starts_with(':') {
        return false;
    }
    valid_http_endpoint_uri(&format!("{scheme}://{authority}"))
}
