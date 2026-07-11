//! Core evaluation entry points for ARM expressions.
//!
//! Every public function is a thin wrapper that unwraps the outer `[...]` and
//! delegates to [`static_expression_value_inner`], the recursive workhorse.
//! Recursion tracks a `depth` counter capped by [`MAX_STATIC_EVAL_DEPTH`].
//! When any sub-expression is opaque (references runtime data, unknown
//! functions, etc.) evaluation returns `None` and callers keep the original
//! expression text.

use super::{
    ArmFunctionDefinition, ArmStaticScope, ArmValueType, ArmValues, MAX_STATIC_EVAL_DEPTH,
    StaticStringFragment,
    format::{format_literal, format_literal_fragments},
    json_fragments::{
        collect_json_string_fragments, static_json_object_entries, static_json_object_keys,
    },
    syntax::{
        arm_array_index_accessor, arm_dot_accessor, arm_function_args, arm_function_call,
        arm_string_literal, full_expression_inner, is_full_expression,
    },
};
use std::collections::{BTreeMap, BTreeSet};

/// Materialize `text` into a sequence of static string fragments.
///
/// When the expression evaluates fully, string leaves of the result are
/// returned as complete, self-contained fragments. When it evaluates only
/// partially (e.g. a `concat(...)` around an opaque reference), the returned
/// vector interleaves the resolvable pieces and marks each with side-extension
/// flags so callers can reason about tokens that may straddle the boundary
/// with an unresolved chunk.
pub(crate) fn static_expression_string_fragments_with_scope(
    text: &str,
    scope: ArmStaticScope<'_>,
) -> Vec<StaticStringFragment> {
    let Some(inner) = full_expression_inner(text) else {
        return Vec::new();
    };
    if let Some(value) = static_expression_value_inner(inner, scope, 0) {
        let mut values = Vec::new();
        collect_json_string_fragments(&value, &mut values);
        values
    } else {
        static_string_fragments(inner, scope)
    }
}

/// Return the object-key set of an expression that evaluates to a JSON object,
/// with no scope information available. Convenience over the scoped form.
pub(crate) fn static_expression_object_keys(text: &str) -> Option<BTreeSet<String>> {
    static_expression_object_keys_with_scope(text, ArmStaticScope::default())
}

/// Return the object-key set for `text` under `scope`.
///
/// First tries a full evaluation; if that fails, falls back to the `json(...)`
/// case where the argument is a static JSON string literal whose keys can be
/// extracted textually without parsing embedded expressions.
pub(crate) fn static_expression_object_keys_with_scope(
    text: &str,
    scope: ArmStaticScope<'_>,
) -> Option<BTreeSet<String>> {
    if let Some(serde_json::Value::Object(object)) = static_expression_value_with_scope(text, scope)
    {
        return Some(object.keys().cloned().collect());
    }

    let inner = full_expression_inner(text)?;
    let args = arm_function_args(inner, "json")?;
    let [arg] = args.as_slice() else {
        return None;
    };
    let keys = static_string_fragments(arg, scope)
        .into_iter()
        .flat_map(|fragment| static_json_object_keys(&fragment.value))
        .collect::<BTreeSet<_>>();
    (!keys.is_empty()).then_some(keys)
}

/// Return `(key, value)` entries for an expression that evaluates to an object.
///
/// Falls back through: full evaluation → partial `union(...)` merging where
/// some branches may be opaque → `json(...)` textual extraction.
pub(crate) fn static_expression_object_entries_with_scope(
    text: &str,
    scope: ArmStaticScope<'_>,
) -> Option<BTreeMap<String, serde_json::Value>> {
    if let Some(serde_json::Value::Object(object)) = static_expression_value_with_scope(text, scope)
    {
        return Some(object.into_iter().collect());
    }

    let inner = full_expression_inner(text)?;
    if let Some(entries) = partial_static_object_entries(inner, scope, 0) {
        return Some(entries);
    }
    let args = arm_function_args(inner, "json")?;
    let [arg] = args.as_slice() else {
        return None;
    };
    let entries = static_string_fragments(arg, scope)
        .into_iter()
        .flat_map(|fragment| static_json_object_entries(&fragment.value))
        .collect::<BTreeMap<_, _>>();
    (!entries.is_empty()).then_some(entries)
}

// Best-effort object-entry extraction for a `union(...)` where some branches
// may not evaluate. When an opaque branch is encountered later branches still
// contribute — we conservatively discard earlier accumulated entries because
// the opaque branch might have shadowed them.
fn partial_static_object_entries(
    expr: &str,
    scope: ArmStaticScope<'_>,
    depth: usize,
) -> Option<BTreeMap<String, serde_json::Value>> {
    if depth > MAX_STATIC_EVAL_DEPTH {
        return None;
    }
    if let Some(entries) = partial_static_object_entries_from_scoped_value(expr, scope, depth + 1) {
        return Some(entries);
    }
    let args = arm_function_args(expr, "union")?;
    let mut entries = BTreeMap::new();
    for arg in args {
        if let Some(serde_json::Value::Object(object)) =
            static_expression_value_inner(arg, scope, depth + 1)
        {
            merge_partial_static_object_entries(&mut entries, object);
        } else if let Some(nested) = partial_static_object_entries(arg, scope, depth + 1) {
            entries.clear();
            merge_partial_static_object_entries(&mut entries, nested);
        } else {
            // Fully opaque branch: prior static entries could be shadowed, so
            // clear them and let subsequent branches re-establish the map.
            entries.clear();
        }
    }
    (!entries.is_empty()).then_some(entries)
}

fn merge_partial_static_object_entries(
    target: &mut BTreeMap<String, serde_json::Value>,
    source: impl IntoIterator<Item = (String, serde_json::Value)>,
) {
    for (key, value) in source {
        match (target.get_mut(&key), value) {
            (
                Some(serde_json::Value::Object(target_child)),
                serde_json::Value::Object(source_child),
            ) => {
                merge_union_object(target_child, source_child);
            }
            (_, value) => {
                target.insert(key, value);
            }
        }
    }
}

// Handle the common shape `variables('v')` / `parameters('p')` where the
// stored value is itself an object literal or an ARM expression that yields an
// object. Lets `union(variables('v'), ...)` see through one level of indirection.
fn partial_static_object_entries_from_scoped_value(
    expr: &str,
    scope: ArmStaticScope<'_>,
    depth: usize,
) -> Option<BTreeMap<String, serde_json::Value>> {
    let call = arm_function_call(expr)?;
    if !call.tail.trim().is_empty() {
        return None;
    }
    let [arg] = call.args.as_slice() else {
        return None;
    };
    let name = static_string_value(arg, scope, depth + 1)?;
    let value = if call.name.eq_ignore_ascii_case("variables") {
        arm_values_get_ignore_case(scope.variables?, &name)?
    } else if call.name.eq_ignore_ascii_case("parameters") {
        arm_values_get_ignore_case(scope.parameters?, &name)?
    } else {
        return None;
    };
    if let serde_json::Value::Object(object) = value.clone() {
        return Some(object.into_iter().collect());
    }
    let text = value.as_str()?;
    if let Some(serde_json::Value::Object(object)) = static_expression_value_with_scope(text, scope)
    {
        return Some(object.into_iter().collect());
    }
    let inner = full_expression_inner(text)?;
    partial_static_object_entries(inner, scope, depth + 1)
}

/// Evaluate `text` with an empty scope. Only pure literals and side-effect-free
/// arithmetic resolve here; anything that reads parameters/variables returns `None`.
pub(crate) fn static_expression_value(text: &str) -> Option<serde_json::Value> {
    static_expression_value_with_variables(text, None)
}

/// Evaluate `text` and require the result to be a string.
pub(crate) fn static_expression_string(text: &str) -> Option<String> {
    let serde_json::Value::String(value) = static_expression_value(text)? else {
        return None;
    };
    Some(value)
}

/// Evaluate `text` under a scope that only exposes `variables`. Convenience for
/// legacy callers predating the full [`ArmStaticScope`].
pub(crate) fn static_expression_value_with_variables(
    text: &str,
    variables: Option<&ArmValues>,
) -> Option<serde_json::Value> {
    static_expression_value_with_scope(text, ArmStaticScope::from_variables(variables))
}

/// Evaluate `text` under a full scope. Returns `None` when the expression is
/// not a well-formed `[...]` or when any sub-expression is opaque.
pub(crate) fn static_expression_value_with_scope(
    text: &str,
    scope: ArmStaticScope<'_>,
) -> Option<serde_json::Value> {
    static_expression_value_inner(full_expression_inner(text)?, scope, 0)
}

/// Best-effort return-type inference. Falls back to the declared parameter
/// type when the value itself cannot be materialized — e.g. a top-level
/// `parameters('x')` with no bound value but a known `type: "string"` in the
/// template's parameter declarations.
pub(crate) fn expression_result_type(
    text: &str,
    scope: ArmStaticScope<'_>,
) -> Option<ArmValueType> {
    if let Some(value) = static_expression_value_with_scope(text, scope) {
        return match value {
            serde_json::Value::Array(_) => Some(ArmValueType::Array),
            serde_json::Value::Bool(_) => Some(ArmValueType::Bool),
            serde_json::Value::Number(number) if number.is_i64() || number.is_u64() => {
                Some(ArmValueType::Int)
            }
            serde_json::Value::Object(_) => Some(ArmValueType::Object),
            serde_json::Value::String(_) => Some(ArmValueType::String),
            serde_json::Value::Null | serde_json::Value::Number(_) => None,
        };
    }

    let expr = full_expression_inner(text)?;
    let call = arm_function_call(expr)?;
    if !call.name.eq_ignore_ascii_case("parameters") || !call.tail.trim().is_empty() {
        return None;
    }
    let [name] = call.args.as_slice() else {
        return None;
    };
    let name = static_string_value(name, scope, 0)?;
    let parameter_type = arm_values_get_ignore_case(scope.parameter_types?, &name)?.as_str()?;
    ArmValueType::from_parameter_type(parameter_type)
}

/// Walk a JSON value and inline any embedded `[...]` strings that fully
/// evaluate. Non-static strings are left as-is.
///
/// Returns `None` only on catastrophic failure; typically returns `Some(new)`.
/// Callers detect "nothing changed" by comparing input and output with `!=`
/// rather than relying on a distinguished sentinel — the whole tree may have
/// been rebuilt structurally-identically when nothing was materializable.
pub(crate) fn materialize_static_expressions_with_scope(
    value: serde_json::Value,
    scope: ArmStaticScope<'_>,
) -> Option<serde_json::Value> {
    materialize_static_json_value(value, scope, 0)
}

// The recursive workhorse. Expects `expr` to be the *inside* of the outer
// `[...]` (unwrapped by the caller) and evaluates one function call at a time,
// resolving each argument recursively. Every branch bumps `depth` because the
// evaluator is otherwise unbounded via user-defined functions.
fn static_expression_value_inner(
    expr: &str,
    scope: ArmStaticScope<'_>,
    depth: usize,
) -> Option<serde_json::Value> {
    if depth > MAX_STATIC_EVAL_DEPTH {
        return None;
    }
    if let Some(value) = static_scalar_value(expr) {
        return Some(value);
    }

    let call = arm_function_call(expr)?;
    // ARM function names are case-insensitive; normalize once.
    let function_name = call.name.to_ascii_lowercase();
    let args = call.args;
    let tail = call.tail;

    // User-defined functions shadow built-ins by name.
    if let Some(function) = scope
        .functions
        .and_then(|functions| functions.get(&function_name))
    {
        return static_user_function_value(function, &args, tail, scope, depth + 1);
    }

    match function_name.as_str() {
        "variables" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let name = static_string_value(arg, scope, depth + 1)?;
            let value = arm_values_get_ignore_case(scope.variables?, &name)?.clone();
            let value = materialize_static_json_value(value, scope, depth + 1)?;
            apply_arm_accessors(value, tail, scope, depth + 1)
        }
        "parameters" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let name = static_string_value(arg, scope, depth + 1)?;
            let value = arm_values_get_ignore_case(scope.parameters?, &name)?.clone();
            let value = materialize_static_json_value(value, scope, depth + 1)?;
            apply_arm_accessors(value, tail, scope, depth + 1)
        }
        "createobject" if !tail.trim().is_empty() => {
            let value = static_create_object_value(args, scope, depth + 1)?;
            apply_arm_accessors(value, tail, scope, depth + 1)
        }
        // Property/index accessors after a call are only meaningful for
        // functions returning composite values (handled above). Anything else
        // followed by a `.foo` or `[i]` tail is unsupported.
        _ if !tail.trim().is_empty() => None,
        "true" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            arg.trim()
                .is_empty()
                .then_some(serde_json::Value::Bool(true))
        }
        "false" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            arg.trim()
                .is_empty()
                .then_some(serde_json::Value::Bool(false))
        }
        "bool" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let value = static_expression_value_inner(arg, scope, depth + 1)?;
            static_bool_value(value).map(serde_json::Value::Bool)
        }
        "empty" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let value = static_expression_value_inner(arg, scope, depth + 1)?;
            static_empty_value(value).map(serde_json::Value::Bool)
        }
        "not" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let value = static_expression_value_inner(arg, scope, depth + 1)?;
            Some(serde_json::Value::Bool(!value.as_bool()?))
        }
        "and" => {
            if args.len() < 2 {
                return None;
            }
            // Short-circuit on false: a definitive `false` decides the result
            // even if other args are opaque. Only bail when the outcome
            // genuinely depends on an unresolved arg.
            let mut unresolved = false;
            for arg in args {
                match static_expression_value_inner(arg, scope, depth + 1)
                    .and_then(|value| value.as_bool())
                {
                    Some(false) => return Some(serde_json::Value::Bool(false)),
                    Some(true) => {}
                    None => unresolved = true,
                }
            }
            (!unresolved).then_some(serde_json::Value::Bool(true))
        }
        "or" => {
            if args.len() < 2 {
                return None;
            }
            // Symmetric short-circuit: a single `true` decides regardless of
            // opaque neighbours.
            let mut unresolved = false;
            for arg in args {
                match static_expression_value_inner(arg, scope, depth + 1)
                    .and_then(|value| value.as_bool())
                {
                    Some(true) => return Some(serde_json::Value::Bool(true)),
                    Some(false) => {}
                    None => unresolved = true,
                }
            }
            (!unresolved).then_some(serde_json::Value::Bool(false))
        }
        "if" => {
            let [condition, when_true, when_false] = args.as_slice() else {
                return None;
            };
            let condition = static_expression_value_inner(condition, scope, depth + 1)?;
            let selected = match condition {
                serde_json::Value::Bool(true) => when_true,
                serde_json::Value::Bool(false) => when_false,
                _ => return None,
            };
            static_expression_value_inner(selected, scope, depth + 1)
        }
        "coalesce" => {
            if args.is_empty() {
                return None;
            }
            for arg in args {
                let value = static_expression_value_inner(arg, scope, depth + 1)?;
                if !value.is_null() {
                    return Some(value);
                }
            }
            Some(serde_json::Value::Null)
        }
        "equals" => {
            let [left, right] = args.as_slice() else {
                return None;
            };
            let left = static_expression_value_inner(left, scope, depth + 1)?;
            let right = static_expression_value_inner(right, scope, depth + 1)?;
            Some(serde_json::Value::Bool(left == right))
        }
        "contains" => {
            let [container, item] = args.as_slice() else {
                return None;
            };
            let container = static_expression_value_inner(container, scope, depth + 1)?;
            let item = static_expression_value_inner(item, scope, depth + 1)?;
            static_contains_value(container, item).map(serde_json::Value::Bool)
        }
        "startswith" => {
            let [value, prefix] = args.as_slice() else {
                return None;
            };
            let value = static_string_value(value, scope, depth + 1)?;
            let prefix = static_string_value(prefix, scope, depth + 1)?;
            // ARM's startsWith is case-insensitive.
            Some(serde_json::Value::Bool(
                value.to_lowercase().starts_with(&prefix.to_lowercase()),
            ))
        }
        "endswith" => {
            let [value, suffix] = args.as_slice() else {
                return None;
            };
            let value = static_string_value(value, scope, depth + 1)?;
            let suffix = static_string_value(suffix, scope, depth + 1)?;
            Some(serde_json::Value::Bool(
                value.to_lowercase().ends_with(&suffix.to_lowercase()),
            ))
        }
        "greater" => static_comparison_value(args, scope, depth + 1, |ordering| ordering.is_gt())
            .map(serde_json::Value::Bool),
        "greaterorequals" => {
            static_comparison_value(args, scope, depth + 1, |ordering| ordering.is_ge())
                .map(serde_json::Value::Bool)
        }
        "less" => static_comparison_value(args, scope, depth + 1, |ordering| ordering.is_lt())
            .map(serde_json::Value::Bool),
        "lessorequals" => {
            static_comparison_value(args, scope, depth + 1, |ordering| ordering.is_le())
                .map(serde_json::Value::Bool)
        }
        "length" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let value = static_expression_value_inner(arg, scope, depth + 1)?;
            let length = match value {
                serde_json::Value::String(text) => text.chars().count(),
                serde_json::Value::Array(values) => values.len(),
                serde_json::Value::Object(values) => values.len(),
                serde_json::Value::Null
                | serde_json::Value::Bool(_)
                | serde_json::Value::Number(_) => {
                    return None;
                }
            };
            Some(serde_json::Value::Number(serde_json::Number::from(
                length as u64,
            )))
        }
        "int" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let value = static_expression_value_inner(arg, scope, depth + 1)?;
            static_int_value(value)
                .map(serde_json::Number::from)
                .map(serde_json::Value::Number)
        }
        "add" => {
            let [left, right] = args.as_slice() else {
                return None;
            };
            let left = static_expression_value_inner(left, scope, depth + 1)?;
            let right = static_expression_value_inner(right, scope, depth + 1)?;
            static_int_value(left)
                .zip(static_int_value(right))
                .and_then(|(left, right)| left.checked_add(right))
                .map(serde_json::Number::from)
                .map(serde_json::Value::Number)
        }
        "sub" => {
            let [left, right] = args.as_slice() else {
                return None;
            };
            let left = static_expression_value_inner(left, scope, depth + 1)?;
            let right = static_expression_value_inner(right, scope, depth + 1)?;
            static_int_value(left)
                .zip(static_int_value(right))
                .and_then(|(left, right)| left.checked_sub(right))
                .map(serde_json::Number::from)
                .map(serde_json::Value::Number)
        }
        "format" => static_format_value(args, scope, depth + 1).map(serde_json::Value::String),
        "join" => static_join_value(args, scope, depth + 1).map(serde_json::Value::String),
        "substring" => {
            static_substring_value(args, scope, depth + 1).map(serde_json::Value::String)
        }
        "replace" => {
            let [original, old, new] = args.as_slice() else {
                return None;
            };
            let original = static_string_value(original, scope, depth + 1)?;
            let old = static_string_value(old, scope, depth + 1)?;
            let new = static_string_value(new, scope, depth + 1)?;
            Some(serde_json::Value::String(original.replace(&old, &new)))
        }
        "tolower" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let value = static_string_value(arg, scope, depth + 1)?;
            Some(serde_json::Value::String(value.to_lowercase()))
        }
        "toupper" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let value = static_string_value(arg, scope, depth + 1)?;
            Some(serde_json::Value::String(value.to_uppercase()))
        }
        "base64tostring" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let encoded = static_string_value(arg, scope, depth + 1)?;
            Some(serde_json::Value::String(static_base64_to_string(
                &encoded,
            )?))
        }
        "base64tojson" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let encoded = static_string_value(arg, scope, depth + 1)?;
            let decoded = static_base64_to_string(&encoded)?;
            serde_json::from_str(&decoded).ok()
        }
        "string" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let value = static_expression_value_inner(arg, scope, depth + 1)?;
            static_arm_string_value(value).map(serde_json::Value::String)
        }
        "first" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let value = static_expression_value_inner(arg, scope, depth + 1)?;
            match value {
                serde_json::Value::Array(values) => values.into_iter().next(),
                serde_json::Value::String(value) => value
                    .chars()
                    .next()
                    .map(|value| serde_json::Value::String(value.to_string())),
                _ => None,
            }
        }
        "copyindex" => static_copy_index_value(args, scope, depth + 1),
        "concat" => static_concat_value(args, scope, depth + 1),
        "null" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            if arg.trim().is_empty() {
                return Some(serde_json::Value::Null);
            }
            None
        }
        "json" => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let value = static_string_value(arg, scope, depth + 1)?;
            serde_json::from_str(&value).ok()
        }
        "union" => static_union_value(args, scope, depth + 1),
        "createobject" => static_create_object_value(args, scope, depth + 1),
        "createarray" => static_create_array_value(args, scope, depth + 1),
        _ => None,
    }
}

fn arm_values_get_ignore_case<'a>(
    values: &'a ArmValues,
    name: &str,
) -> Option<&'a serde_json::Value> {
    values.get(name).or_else(|| {
        values
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    })
}

// Invoke a user-defined ARM function. Arguments are eagerly evaluated in the
// caller's scope, then the body is materialized under a fresh scope where
// only the bound parameters and the user-function table are visible — user
// functions cannot see the outer template's variables or copy loops.
fn static_user_function_value(
    function: &ArmFunctionDefinition,
    args: &[&str],
    tail: &str,
    outer_scope: ArmStaticScope<'_>,
    depth: usize,
) -> Option<serde_json::Value> {
    // The parser reports `foo()` as one empty-string argument; normalize it to
    // "no arguments" so arity checks below line up with zero-parameter functions.
    let args = match args {
        [arg] if arg.trim().is_empty() => &[][..],
        args => args,
    };
    if args.len() != function.parameter_names.len() {
        return None;
    }

    let mut parameters = ArmValues::new();
    for (name, arg) in function.parameter_names.iter().zip(args) {
        let value = static_expression_value_inner(arg, outer_scope, depth + 1)?;
        parameters.insert(name.clone(), value);
    }
    let function_scope = ArmStaticScope {
        variables: None,
        parameters: Some(&parameters),
        parameter_types: None,
        functions: outer_scope.functions,
        copy_index: None,
    };
    let value = materialize_static_json_value(function.output.clone(), function_scope, depth + 1)?;
    apply_arm_accessors(value, tail, function_scope, depth + 1)
}

// Recursive materialization: walk the JSON tree; whenever a string is a full
// `[...]` expression try to evaluate it, otherwise preserve the original value.
// Depth cap returns the value untouched (rather than erroring) so partial
// materialization still succeeds up to the cap.
fn materialize_static_json_value(
    value: serde_json::Value,
    scope: ArmStaticScope<'_>,
    depth: usize,
) -> Option<serde_json::Value> {
    if depth > MAX_STATIC_EVAL_DEPTH {
        return Some(value);
    }
    match value {
        serde_json::Value::String(text) if is_full_expression(&text) => Some(
            // Opaque sub-expressions keep the original string verbatim so the
            // caller downstream can still see and analyse the raw ARM syntax.
            static_expression_value_inner(full_expression_inner(&text)?, scope, depth + 1)
                .unwrap_or(serde_json::Value::String(text)),
        ),
        serde_json::Value::Array(values) => Some(serde_json::Value::Array(
            values
                .into_iter()
                .map(|value| {
                    materialize_static_json_value(value.clone(), scope, depth + 1).unwrap_or(value)
                })
                .collect(),
        )),
        serde_json::Value::Object(values) => {
            let mut object = serde_json::Map::new();
            for (key, value) in values {
                object.insert(
                    key,
                    materialize_static_json_value(value.clone(), scope, depth + 1).unwrap_or(value),
                );
            }
            Some(serde_json::Value::Object(object))
        }
        value => Some(value),
    }
}

// Consume the trailing chain of `.prop` and `[index]` / `['key']` accessors
// after a function call, drilling into the produced value. Each intermediate
// value is re-materialized so nested ARM expressions inside data structures
// evaluate lazily on demand.
fn apply_arm_accessors(
    mut value: serde_json::Value,
    mut tail: &str,
    scope: ArmStaticScope<'_>,
    depth: usize,
) -> Option<serde_json::Value> {
    while !tail.trim().is_empty() {
        tail = tail.trim_start();
        if let Some(rest) = tail.strip_prefix('.') {
            let (property, rest) = arm_dot_accessor(rest)?;
            value = value.get(property)?.clone();
            value = materialize_static_json_value(value, scope, depth + 1)?;
            tail = rest;
        } else {
            let rest = tail.strip_prefix('[')?;
            let rest = rest.trim_start();
            if let Some((index, rest)) = arm_array_index_accessor(rest) {
                value = value.as_array()?.get(index)?.clone();
                tail = rest;
            } else {
                let (property, end) = arm_string_literal(rest, 0)?;
                let rest = rest[end..].trim_start();
                let rest = rest.strip_prefix(']')?;
                value = value.get(&property)?.clone();
                tail = rest;
            }
            value = materialize_static_json_value(value, scope, depth + 1)?;
        }
    }
    Some(value)
}

fn static_create_object_value(
    args: Vec<&str>,
    scope: ArmStaticScope<'_>,
    depth: usize,
) -> Option<serde_json::Value> {
    if args.len() == 1 && args[0].trim().is_empty() {
        return Some(serde_json::Value::Object(serde_json::Map::new()));
    }
    if !args.len().is_multiple_of(2) {
        return None;
    }
    let mut object = serde_json::Map::new();
    for pair in args.chunks(2) {
        let key = static_string_value(pair[0], scope, depth + 1)?;
        let value = static_expression_value_inner(pair[1], scope, depth + 1)?;
        object.insert(key, value);
    }
    Some(serde_json::Value::Object(object))
}

fn static_create_array_value(
    args: Vec<&str>,
    scope: ArmStaticScope<'_>,
    depth: usize,
) -> Option<serde_json::Value> {
    if args.len() == 1 && args[0].trim().is_empty() {
        return Some(serde_json::Value::Array(Vec::new()));
    }
    let values = args
        .into_iter()
        .map(|arg| static_expression_value_inner(arg, scope, depth + 1))
        .collect::<Option<Vec<_>>>()?;
    Some(serde_json::Value::Array(values))
}

fn static_concat_value(
    args: Vec<&str>,
    scope: ArmStaticScope<'_>,
    depth: usize,
) -> Option<serde_json::Value> {
    if args.is_empty() {
        return Some(serde_json::Value::String(String::new()));
    }
    let mut args = args.into_iter();
    let first_arg = args.next()?;
    let first = static_expression_value_inner(first_arg, scope, depth + 1)?;
    match first {
        serde_json::Value::Array(mut array) => {
            for arg in args {
                let serde_json::Value::Array(next) =
                    static_expression_value_inner(arg, scope, depth + 1)?
                else {
                    return None;
                };
                array.extend(next);
            }
            Some(serde_json::Value::Array(array))
        }
        serde_json::Value::String(mut out) => {
            for arg in args {
                out.push_str(&static_string_value(arg, scope, depth + 1)?);
            }
            Some(serde_json::Value::String(out))
        }
        serde_json::Value::Bool(value) => {
            let mut out = value.to_string();
            for arg in args {
                out.push_str(&static_string_value(arg, scope, depth + 1)?);
            }
            Some(serde_json::Value::String(out))
        }
        serde_json::Value::Number(value) => {
            let mut out = value.to_string();
            for arg in args {
                out.push_str(&static_string_value(arg, scope, depth + 1)?);
            }
            Some(serde_json::Value::String(out))
        }
        serde_json::Value::Null | serde_json::Value::Object(_) => None,
    }
}

fn static_union_value(
    args: Vec<&str>,
    scope: ArmStaticScope<'_>,
    depth: usize,
) -> Option<serde_json::Value> {
    let mut values = args
        .into_iter()
        .map(|arg| static_expression_value_inner(arg, scope, depth + 1));
    let first = values.next()??;
    match first {
        serde_json::Value::Object(mut object) => {
            for value in values {
                let serde_json::Value::Object(next) = value? else {
                    return None;
                };
                merge_union_object(&mut object, next);
            }
            Some(serde_json::Value::Object(object))
        }
        serde_json::Value::Array(mut array) => {
            for value in values {
                let serde_json::Value::Array(next) = value? else {
                    return None;
                };
                for item in next {
                    if !array.contains(&item) {
                        array.push(item);
                    }
                }
            }
            Some(serde_json::Value::Array(array))
        }
        _ => None,
    }
}

fn merge_union_object(
    target: &mut serde_json::Map<String, serde_json::Value>,
    source: serde_json::Map<String, serde_json::Value>,
) {
    for (key, value) in source {
        match (target.get_mut(&key), value) {
            (
                Some(serde_json::Value::Object(target_child)),
                serde_json::Value::Object(source_child),
            ) => {
                merge_union_object(target_child, source_child);
            }
            (_, value) => {
                target.insert(key, value);
            }
        }
    }
}

fn static_join_value(args: Vec<&str>, scope: ArmStaticScope<'_>, depth: usize) -> Option<String> {
    let [array, delimiter] = args.as_slice() else {
        return None;
    };
    let serde_json::Value::Array(values) = static_expression_value_inner(array, scope, depth + 1)?
    else {
        return None;
    };
    let delimiter = static_string_value(delimiter, scope, depth + 1)?;
    let values = values
        .into_iter()
        .map(static_json_scalar_to_string)
        .collect::<Option<Vec<_>>>()?;
    Some(values.join(&delimiter))
}

fn static_substring_value(
    args: Vec<&str>,
    scope: ArmStaticScope<'_>,
    depth: usize,
) -> Option<String> {
    let [text, start, length] = args.as_slice() else {
        return None;
    };
    let text = static_string_value(text, scope, depth + 1)?;
    let start = static_int_value(static_expression_value_inner(start, scope, depth + 1)?)?;
    let length = static_int_value(static_expression_value_inner(length, scope, depth + 1)?)?;
    if start < 0 || length < 0 {
        return None;
    }
    let start = usize::try_from(start).ok()?;
    let length = usize::try_from(length).ok()?;
    let chars = text.chars().collect::<Vec<_>>();
    if start.checked_add(length)? > chars.len() {
        return None;
    }
    Some(chars[start..start + length].iter().collect())
}

// Produce fragments for `concat(a, b, c, ...)` where some `a`/`b`/`c` may be
// opaque. Consecutive static pieces are coalesced; each fragment tracks
// whether an opaque neighbour sits to its left or right so callers can decide
// whether a token at that end could straddle the boundary.
fn static_concat_fragments(
    args: Vec<&str>,
    scope: ArmStaticScope<'_>,
) -> Vec<StaticStringFragment> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut current_can_extend_left = false;
    // Set whenever the previous arg was opaque — the *next* fragment we start
    // will inherit this as its `can_extend_left`.
    let mut next_can_extend_left = false;
    for arg in args {
        if let Some(value) = static_string_value(arg, scope, 0) {
            if current.is_empty() {
                current_can_extend_left = next_can_extend_left;
            }
            next_can_extend_left = false;
            current.push_str(&value);
        } else if !current.is_empty() {
            values.push(StaticStringFragment {
                value: std::mem::take(&mut current),
                can_extend_left: current_can_extend_left,
                can_extend_right: true,
            });
            current_can_extend_left = false;
            next_can_extend_left = true;
        } else {
            next_can_extend_left = true;
        }
    }
    if !current.is_empty() {
        values.push(StaticStringFragment {
            value: current,
            can_extend_left: current_can_extend_left,
            can_extend_right: false,
        });
    }
    values
}

fn static_format_value(args: Vec<&str>, scope: ArmStaticScope<'_>, depth: usize) -> Option<String> {
    let [format, replacements @ ..] = args.as_slice() else {
        return None;
    };
    let format = static_string_value(format, scope, depth + 1)?;
    let replacements = replacements
        .iter()
        .map(|arg| static_string_value(arg, scope, depth + 1))
        .collect::<Option<Vec<_>>>()?;
    format_literal(&format, &replacements)
}

fn static_string_fragments(expr: &str, scope: ArmStaticScope<'_>) -> Vec<StaticStringFragment> {
    let expr = expr.trim();
    if let Some(args) = arm_function_args(expr, "concat") {
        return static_concat_fragments(args, scope);
    }
    if let Some(args) = arm_function_args(expr, "format") {
        return static_format_fragments(args, scope);
    }
    if let Some(args) = arm_function_args(expr, "json") {
        let [arg] = args.as_slice() else {
            return Vec::new();
        };
        return static_string_fragments(arg, scope);
    }
    static_string_value(expr, scope, 0)
        .into_iter()
        .map(|value| StaticStringFragment {
            value,
            can_extend_left: false,
            can_extend_right: false,
        })
        .collect()
}

fn static_format_fragments(
    args: Vec<&str>,
    scope: ArmStaticScope<'_>,
) -> Vec<StaticStringFragment> {
    let [format, replacements @ ..] = args.as_slice() else {
        return Vec::new();
    };
    let Some(format) = static_string_value(format, scope, 0) else {
        return Vec::new();
    };
    let replacements = replacements
        .iter()
        .map(|arg| {
            let value = static_string_value(arg, scope, 0);
            let can_extend_to_wdl_escape =
                value.is_none() && dynamic_string_fragment_can_start_with_at(arg, scope);
            super::format::FormatFragmentReplacement {
                value,
                can_extend_to_wdl_escape,
            }
        })
        .collect::<Vec<_>>();
    format_literal_fragments(&format, &replacements).unwrap_or_default()
}

// A `parameters('name')` reference whose declared type is (secure) string
// might expand to text starting with `@`, which would collide with Logic Apps
// WDL escaping. Anything non-string cannot; everything else is treated
// conservatively as potentially `@`-starting.
fn dynamic_string_fragment_can_start_with_at(expr: &str, scope: ArmStaticScope<'_>) -> bool {
    let Some(args) = arm_function_args(expr.trim(), "parameters") else {
        return true;
    };
    let [name] = args.as_slice() else {
        return true;
    };
    let Some(name) = static_string_value(name, scope, 0) else {
        return true;
    };
    let Some(parameter_type) = scope
        .parameter_types
        .and_then(|types| arm_values_get_ignore_case(types, &name))
        .and_then(serde_json::Value::as_str)
    else {
        return true;
    };
    parameter_type.eq_ignore_ascii_case("string")
        || parameter_type.eq_ignore_ascii_case("secureString")
}

fn static_string_value(expr: &str, scope: ArmStaticScope<'_>, depth: usize) -> Option<String> {
    match static_expression_value_inner(expr.trim(), scope, depth + 1)? {
        serde_json::Value::String(value) => Some(value),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            None
        }
    }
}

// Bare literals valid inside an ARM expression: single-quoted strings,
// `true`/`false`, and decimal integers. No floats — ARM expression grammar
// doesn't allow them.
fn static_scalar_value(expr: &str) -> Option<serde_json::Value> {
    let expr = expr.trim();
    if let Some((value, end)) = arm_string_literal(expr, 0)
        && expr[end..].trim().is_empty()
    {
        return Some(serde_json::Value::String(value));
    }
    if expr.eq_ignore_ascii_case("true") {
        return Some(serde_json::Value::Bool(true));
    }
    if expr.eq_ignore_ascii_case("false") {
        return Some(serde_json::Value::Bool(false));
    }
    expr.parse::<i64>()
        .ok()
        .map(serde_json::Number::from)
        .map(serde_json::Value::Number)
}

fn static_empty_value(value: serde_json::Value) -> Option<bool> {
    match value {
        serde_json::Value::Null => Some(true),
        serde_json::Value::String(text) => Some(text.is_empty()),
        serde_json::Value::Array(values) => Some(values.is_empty()),
        serde_json::Value::Object(values) => Some(values.is_empty()),
        serde_json::Value::Bool(_) | serde_json::Value::Number(_) => None,
    }
}

fn static_contains_value(container: serde_json::Value, item: serde_json::Value) -> Option<bool> {
    match container {
        serde_json::Value::String(text) => {
            let item = static_string_or_int_to_string(item)?;
            Some(text.contains(&item))
        }
        serde_json::Value::Array(values) => Some(values.contains(&item)),
        serde_json::Value::Object(values) => {
            let item = static_string_or_int_to_string(item)?;
            Some(values.keys().any(|key| key.eq_ignore_ascii_case(&item)))
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => None,
    }
}

fn static_string_or_int_to_string(value: serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value),
        serde_json::Value::Number(value) if value.is_i64() || value.is_u64() => {
            Some(value.to_string())
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::Array(_)
        | serde_json::Value::Object(_) => None,
    }
}

fn static_comparison_value(
    args: Vec<&str>,
    scope: ArmStaticScope<'_>,
    depth: usize,
    predicate: impl Fn(std::cmp::Ordering) -> bool,
) -> Option<bool> {
    let [left, right] = args.as_slice() else {
        return None;
    };
    let left = static_expression_value_inner(left, scope, depth)?;
    let right = static_expression_value_inner(right, scope, depth)?;
    let ordering = match (left, right) {
        (serde_json::Value::Number(left), serde_json::Value::Number(right)) => {
            left.as_f64()?.partial_cmp(&right.as_f64()?)?
        }
        (serde_json::Value::String(left), serde_json::Value::String(right)) => left.cmp(&right),
        _ => return None,
    };
    Some(predicate(ordering))
}

// ARM `bool()` coerces from bools, "true"/"false" strings (case-insensitive),
// and integers (0 → false, non-zero → true). Floats are rejected — ARM has no
// float arithmetic here.
fn static_bool_value(value: serde_json::Value) -> Option<bool> {
    match value {
        serde_json::Value::Bool(value) => Some(value),
        serde_json::Value::String(value) if value.eq_ignore_ascii_case("true") => Some(true),
        serde_json::Value::String(value) if value.eq_ignore_ascii_case("false") => Some(false),
        serde_json::Value::Number(value) if value.as_i64() == Some(0) => Some(false),
        serde_json::Value::Number(value) if value.as_u64() == Some(0) => Some(false),
        serde_json::Value::Number(value)
            if value.as_i64().is_some() || value.as_u64().is_some() =>
        {
            Some(true)
        }
        _ => None,
    }
}

fn static_int_value(value: serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::Number(value) => value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok())),
        serde_json::Value::String(value) => value.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn static_json_scalar_to_string(value: serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            None
        }
    }
}

fn static_arm_string_value(value: serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value),
        serde_json::Value::Null => None,
        value => serde_json::to_string(&value).ok(),
    }
}

// Resolve `copyIndex()`, `copyIndex(name)`, or `copyIndex(name, offset)`.
// The active `copy_index` layer must match by name; unrelated nested loops
// return `None` so the outer expression stays opaque.
fn static_copy_index_value(
    args: Vec<&str>,
    scope: ArmStaticScope<'_>,
    depth: usize,
) -> Option<serde_json::Value> {
    let copy_index = scope.copy_index?;
    let offset = match args.as_slice() {
        [arg] if arg.trim().is_empty() => 0,
        [name] => {
            let name = static_string_value(name, scope, depth)?;
            if !name.eq_ignore_ascii_case(&copy_index.name) {
                return None;
            }
            0
        }
        [name, offset] => {
            let name = static_string_value(name, scope, depth)?;
            if !name.eq_ignore_ascii_case(&copy_index.name) {
                return None;
            }
            let offset = static_expression_value_inner(offset, scope, depth)?;
            static_int_value(offset)?
        }
        _ => return None,
    };
    copy_index
        .index
        .checked_add(offset)
        .map(serde_json::Number::from)
        .map(serde_json::Value::Number)
}

// Standard Base64 decode. Rolled by hand to avoid pulling in a base64 crate
// just for this rarely-hit code path and to keep the ARM layer dependency-free.
fn static_base64_to_string(value: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut padded = false;

    for ch in value.chars().filter(|ch| !ch.is_whitespace()) {
        if ch == '=' {
            padded = true;
            continue;
        }
        if padded {
            return None;
        }
        let digit = base64_digit(ch)? as u32;
        buffer = (buffer << 6) | digit;
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            bytes.push(((buffer >> bits) & 0xff) as u8);
            buffer &= (1u32 << bits) - 1;
        }
    }

    String::from_utf8(bytes).ok()
}

fn base64_digit(ch: char) -> Option<u8> {
    match ch {
        'A'..='Z' => Some(ch as u8 - b'A'),
        'a'..='z' => Some(ch as u8 - b'a' + 26),
        '0'..='9' => Some(ch as u8 - b'0' + 52),
        '+' => Some(62),
        '/' => Some(63),
        _ => None,
    }
}
