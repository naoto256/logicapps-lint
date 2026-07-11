//! Static evaluator for the subset of ARM template expressions that appear in
//! Azure Logic Apps deployment templates.
//!
//! The evaluator materializes expressions like `[parameters('x')]`,
//! `[variables('y')]`, `[concat(...)]`, `[format(...)]`, and `[copyIndex()]`
//! against an [`ArmStaticScope`]. Anything that references runtime data
//! (e.g. `resourceGroup()`, `listKeys(...)`) is treated as opaque; the caller
//! keeps the original expression and handles the fallback.
//!
//! The layer is deliberately a partial ARM implementation: only what is needed
//! to lint Logic Apps workflow bodies with confidence.

/// Named-value map used for `parameters` and `variables` sections of a template.
///
/// Insertion order is preserved because ARM lookups are case-insensitive but
/// author intent (declaration order) matters for diagnostics.
pub(crate) type ArmValues = serde_json::Map<String, serde_json::Value>;

/// User-defined ARM function table, keyed by lowercased fully-qualified name
/// (e.g. `mynamespace.myfunc`). Sorted for stable iteration in diagnostics.
pub(crate) type ArmFunctions = std::collections::BTreeMap<String, ArmFunctionDefinition>;

/// A user-defined ARM function, ready to be invoked during static evaluation.
///
/// `output` is stored as raw JSON (with embedded `[...]` expressions) and is
/// re-materialized on each call under a fresh scope where `parameters` are
/// bound to the call-site arguments.
#[derive(Clone)]
pub(crate) struct ArmFunctionDefinition {
    /// Positional parameter names, in declaration order.
    pub(crate) parameter_names: Vec<String>,
    /// The function body — an arbitrary JSON value whose strings may contain
    /// ARM expressions that reference the bound parameters.
    pub(crate) output: serde_json::Value,
}

/// Coarse ARM type tag used for return-type inference when a full value cannot
/// be materialized (e.g. a `parameters('x')` reference whose value is unknown
/// but whose declared type is available).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArmValueType {
    Array,
    Bool,
    Int,
    Object,
    String,
}

impl ArmValueType {
    // ARM parameter type strings are case-insensitive; `secure*` variants
    // collapse onto their non-secure counterparts because they have identical
    // runtime shape.
    fn from_parameter_type(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "array" => Some(Self::Array),
            "bool" => Some(Self::Bool),
            "int" => Some(Self::Int),
            "object" | "secureobject" => Some(Self::Object),
            "string" | "securestring" => Some(Self::String),
            _ => None,
        }
    }
}

/// Active `copy` loop context. `copyIndex(name)` / `copyIndex(name, offset)`
/// resolve against this. The `name` allows nested loops to disambiguate.
pub(crate) struct ArmCopyIndex {
    pub(crate) name: String,
    pub(crate) index: i64,
}

/// A slice of a partially-materialized string produced when `concat(...)` or
/// `format(...)` mixes static and opaque pieces.
///
/// The extension flags mark which side of the fragment abuts an opaque region:
/// when `can_extend_*` is true, a token starting at that boundary (notably a
/// Logic Apps WDL `@` escape) may originate from the runtime piece, so callers
/// that scan the fragment for such tokens must not treat the boundary as
/// authoritative.
pub(crate) struct StaticStringFragment {
    pub(crate) value: String,
    pub(crate) can_extend_left: bool,
    pub(crate) can_extend_right: bool,
}

/// Read-only lookup context threaded through every evaluation call.
///
/// `Copy` on purpose: derived scopes (e.g. `with_copy_index`) are cheap to
/// produce and passing by value keeps recursion allocation-free — cloning the
/// underlying maps would be prohibitive for deeply nested expressions.
#[derive(Clone, Copy, Default)]
pub(crate) struct ArmStaticScope<'a> {
    pub(crate) variables: Option<&'a ArmValues>,
    pub(crate) parameters: Option<&'a ArmValues>,
    /// Declared parameter types (from `parameters.<x>.type`), used for the
    /// type-only inference path when the value itself is not resolvable.
    pub(crate) parameter_types: Option<&'a ArmValues>,
    pub(crate) functions: Option<&'a ArmFunctions>,
    pub(crate) copy_index: Option<&'a ArmCopyIndex>,
}

impl<'a> ArmStaticScope<'a> {
    fn from_variables(variables: Option<&'a ArmValues>) -> Self {
        Self {
            variables,
            parameters: None,
            parameter_types: None,
            functions: None,
            copy_index: None,
        }
    }

    /// Layer a `copy` loop context onto an existing scope without cloning any
    /// of the underlying maps — the returned scope reborrows the same slices.
    pub(crate) fn with_copy_index<'b>(self, copy_index: &'b ArmCopyIndex) -> ArmStaticScope<'b>
    where
        'a: 'b,
    {
        ArmStaticScope {
            variables: self.variables,
            parameters: self.parameters,
            parameter_types: self.parameter_types,
            functions: self.functions,
            copy_index: Some(copy_index),
        }
    }
}

// Hard cap on recursive evaluation depth. Guards against pathological or
// mutually-recursive user functions and against deeply nested `concat`/`format`
// trees; anything past this point aborts evaluation and the caller falls back
// to treating the outer expression as opaque.
const MAX_STATIC_EVAL_DEPTH: usize = 32;

mod eval;
mod format;
mod json_fragments;
mod syntax;

pub(crate) use eval::{
    expression_result_type, materialize_static_expressions_with_scope,
    static_expression_object_entries_with_scope, static_expression_object_keys,
    static_expression_string, static_expression_string_fragments_with_scope,
    static_expression_value, static_expression_value_with_scope,
};
pub(crate) use syntax::{full_expression_contains_unquoted_wdl, is_full_expression};
