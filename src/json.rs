//! Span-preserving JSON I/O layer.
//!
//! Thin wrapper over `json-spanned-value` that keeps byte offsets attached to
//! every parsed value so diagnostics can point at exact source ranges without
//! a second parse. All accessors here return borrows into the original
//! `spanned::Value` tree; callers must keep the owning [`JsonFile`] alive for
//! the duration of the borrow.

use crate::diagnostic::ByteSpan;
use json_spanned_value::{Value, spanned};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// A parsed JSON document paired with its filesystem path.
///
/// `value` retains byte spans for every node, which downstream checks feed
/// into [`ByteSpan`] via [`span`].
#[derive(Debug)]
pub struct JsonFile {
    /// Path the document was read from; used verbatim in diagnostics.
    pub path: PathBuf,
    /// Parsed root value with per-node byte spans.
    pub value: spanned::Value,
}

/// Failure modes for [`JsonFile::read`].
///
/// Each variant carries the offending `path` so the CLI can surface a
/// diagnostic anchored at the file even when parsing never completed.
#[derive(Debug, Error)]
pub enum JsonReadError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("failed to decode {path}: {source}")]
    InvalidUtf8 {
        path: PathBuf,
        source: std::string::FromUtf8Error,
    },
}

impl JsonFile {
    /// Parse JSON while preserving byte spans for every value. The linter's
    /// stable test contract uses JSON Pointer, but the core keeps spans from
    /// day one so human output and future editor integrations do not need a
    /// parser swap.
    pub fn read(path: impl AsRef<Path>) -> Result<Self, JsonReadError> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path).map_err(|source| JsonReadError::Io {
            path: path.clone(),
            source,
        })?;
        let source = String::from_utf8(bytes).map_err(|source| JsonReadError::InvalidUtf8 {
            path: path.clone(),
            source,
        })?;
        let value =
            json_spanned_value::from_str(&source).map_err(|source| JsonReadError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Self { path, value })
    }
}

/// Extract the byte range that `value` occupies in its source document.
pub fn span(value: &spanned::Value) -> ByteSpan {
    ByteSpan {
        start: value.start(),
        end: value.end(),
    }
}

/// Look up `key` on an object node, returning `None` for non-objects or misses.
pub fn get<'a>(value: &'a spanned::Value, key: &str) -> Option<&'a spanned::Value> {
    let Value::Object(object) = value.get_ref() else {
        return None;
    };
    object.get(key)
}

/// Borrow `value` as an object map, or return `None` if it is any other kind.
pub fn as_object(
    value: &spanned::Value,
) -> Option<&json_spanned_value::Map<spanned::String, spanned::Value>> {
    let Value::Object(object) = value.get_ref() else {
        return None;
    };
    Some(object)
}

/// Borrow `value` as a string, or return `None` if it is any other kind.
pub fn as_string(value: &spanned::Value) -> Option<&str> {
    let Value::String(text) = value.get_ref() else {
        return None;
    };
    Some(text)
}

/// Drop spans and return a plain `serde_json::Value` tree.
///
/// Returns `None` only if a nested conversion fails; used at the boundary
/// where checks need to hand a value to serde-based helpers.
pub fn to_json_value(value: &spanned::Value) -> Option<serde_json::Value> {
    match value.get_ref() {
        Value::Null => Some(serde_json::Value::Null),
        Value::Bool(value) => Some(serde_json::Value::Bool(*value)),
        Value::Number(value) => Some(serde_json::Value::Number(value.clone())),
        Value::String(value) => Some(serde_json::Value::String(value.clone())),
        Value::Array(values) => values
            .iter()
            .map(to_json_value)
            .collect::<Option<Vec<_>>>()
            .map(serde_json::Value::Array),
        Value::Object(values) => {
            let mut object = serde_json::Map::new();
            for (key, value) in values {
                object.insert(key.to_string(), to_json_value(value)?);
            }
            Some(serde_json::Value::Object(object))
        }
    }
}

/// Re-parse a `serde_json::Value` through the spanned parser so downstream
/// code can uniformly consume `spanned::Value`. Spans point into the
/// synthesized string, not the original document.
pub fn spanned_from_json(value: &serde_json::Value) -> Option<spanned::Value> {
    let source = serde_json::to_string(value).ok()?;
    json_spanned_value::from_str(&source).ok()
}

/// Append `token` to a JSON Pointer `base`, escaping per RFC 6901.
pub fn pointer_join(base: &str, token: &str) -> String {
    if base.is_empty() {
        format!("/{}", escape_pointer_token(token))
    } else {
        format!("{}/{}", base, escape_pointer_token(token))
    }
}

/// Escape a single reference token following RFC 6901: `~` -> `~0`, `/` -> `~1`.
/// Order matters — `~` must be escaped before `/` so `~1` produced by the
/// second pass is not itself rewritten.
pub fn escape_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}
