//! Shape validators for pure-data actions: `Compose`, `Expression`,
//! `JavaScriptCode`, `Join`, `ParseJson`, `PowershellCode`, `Query`,
//! `Select`, and `Table`. These have no external side effects — their input
//! shapes describe pure transformations over the run's data.

use super::super::materialized::arm_optional_property_absent;
use super::*;

const TABLE_FORMATS: &[&str] = &["CSV", "HTML"];
const EXPRESSION_KINDS: &[&str] = &[
    "AddToTime",
    "ConvertTimeZone",
    "CurrentTime",
    "GetFutureTime",
    "GetPastTime",
    "SubtractFromTime",
];

/// Validate a `Compose` action: `inputs` may be any JSON value, so we only
/// require presence.
pub(in crate::check::shape) fn validate_compose_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    require_field(action, action_pointer, "inputs", file, diagnostics);
}

/// Validate a `Join` action: concatenates `inputs.from` (array or WDL) using
/// a single-character `joinWith`. The single-char rule matches the runtime
/// error for multi-char separators.
pub(in crate::check::shape) fn validate_join_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    let inputs_pointer = pointer_join(action_pointer, "inputs");
    require_typed_field(
        inputs,
        &inputs_pointer,
        "from",
        "Join inputs.from must be a string or array",
        file,
        diagnostics,
        |value| as_string(value).is_some() || value.as_array().is_some(),
    );
    require_typed_field(
        inputs,
        &inputs_pointer,
        "joinWith",
        "Join inputs.joinWith must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    if let Some(join_with) = get(inputs, "joinWith")
        && !is_opaque_arm_expression(file, join_with)
        && let Some(text) = as_string(join_with)
        && !crate::wdl::WdlStringValue::classify(text).may_have_char_len(1)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-value",
            &file.path,
            pointer_join(&inputs_pointer, "joinWith"),
            Some(span(join_with)),
            "Join inputs.joinWith must be a single character",
        ));
    }
}

/// Validate a `ParseJson` action: needs `content` (any type — often a WDL
/// expression yielding a string) and a `schema` object used for typing.
pub(in crate::check::shape) fn validate_parse_json_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    let inputs_pointer = pointer_join(action_pointer, "inputs");
    require_typed_field(
        inputs,
        &inputs_pointer,
        "content",
        "ParseJson inputs.content must be present",
        file,
        diagnostics,
        |_| true,
    );
    require_object_field(inputs, &inputs_pointer, "schema", file, diagnostics);
}

/// Validate a `Query` action; shape is a superset of the shared `from`
/// shape with a required `where` predicate.
pub(in crate::check::shape) fn validate_query_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_from_action(action, action_pointer, "Query", file, diagnostics);
}

/// Shared `inputs.from` check for `Query`/`Select`/`Table`. Branches on
/// `action_label` to add per-action requirements (`where` for Query,
/// `format`+`columns` for Table).
pub(in crate::check::shape) fn validate_from_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    action_label: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    require_typed_field(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "from",
        "inputs.from must be a string or array",
        file,
        diagnostics,
        |value| as_string(value).is_some() || value.as_array().is_some(),
    );
    if action_label.eq_ignore_ascii_case("query") {
        require_typed_field(
            inputs,
            &pointer_join(action_pointer, "inputs"),
            "where",
            "Query inputs.where must be a string",
            file,
            diagnostics,
            |value| as_string(value).is_some(),
        );
    }
    if action_label.eq_ignore_ascii_case("table") {
        require_typed_field(
            inputs,
            &pointer_join(action_pointer, "inputs"),
            "format",
            "Table inputs.format must be a string",
            file,
            diagnostics,
            |value| as_string(value).is_some(),
        );
        validate_optional_string_enum(
            inputs,
            &pointer_join(action_pointer, "inputs"),
            "format",
            "Table inputs.format",
            TABLE_FORMATS,
            file,
            diagnostics,
        );
        validate_table_columns(
            inputs,
            &pointer_join(action_pointer, "inputs"),
            file,
            diagnostics,
        );
    }
}

/// Validate a `Table` action: reuses [`validate_from_action`] with the
/// Table-specific `format`/`columns` branch.
pub(in crate::check::shape) fn validate_table_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_from_action(action, action_pointer, "Table", file, diagnostics);
}

/// Validate `Table.inputs.columns`. Columns are required only when the
/// `from` array contains non-object entries — object entries auto-project
/// to headers, so a projection is unnecessary in that case.
pub(in crate::check::shape) fn validate_table_columns(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(columns) =
        get(inputs, "columns").filter(|columns| !arm_optional_property_absent(file, columns))
    else {
        if table_from_requires_columns(inputs, file) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-missing-field",
                &file.path,
                pointer_join(inputs_pointer, "columns"),
                Some(span(inputs)),
                "Table inputs.columns is required when inputs.from contains non-object values",
            ));
        }
        return;
    };
    if is_opaque_arm_expression(file, columns) {
        return;
    }
    let columns_pointer = pointer_join(inputs_pointer, "columns");
    let Some(entries) = columns.as_span_array() else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            columns_pointer,
            Some(span(columns)),
            "Table inputs.columns must be an array",
        ));
        return;
    };
    for (index, column) in entries.iter().enumerate() {
        let column_pointer = pointer_join(&columns_pointer, &index.to_string());
        if is_opaque_arm_expression(file, column) {
            continue;
        }
        if as_object(column).is_none() {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                column_pointer,
                Some(span(column)),
                "Table inputs.columns entries must be objects",
            ));
            continue;
        }
        require_typed_field(
            column,
            &column_pointer,
            "header",
            "Table inputs.columns.header must be a string",
            file,
            diagnostics,
            |value| as_string(value).is_some(),
        );
        require_typed_field(
            column,
            &column_pointer,
            "value",
            "Table inputs.columns.value must be present",
            file,
            diagnostics,
            |_| true,
        );
    }
}

fn table_from_requires_columns(
    inputs: &json_spanned_value::spanned::Value,
    file: &JsonFile,
) -> bool {
    let Some(entries) = get(inputs, "from").and_then(|from| from.as_span_array()) else {
        return false;
    };
    entries
        .iter()
        .any(|entry| table_entry_is_statically_non_object(entry, file))
}

fn table_entry_is_statically_non_object(
    entry: &json_spanned_value::spanned::Value,
    file: &JsonFile,
) -> bool {
    if is_opaque_arm_expression(file, entry) {
        return false;
    }
    if let Some(text) = as_string(entry) {
        return !wdl_string_is_full_expression(text);
    }
    as_object(entry).is_none()
}

/// Validate a `Select` action: `from` (source) + `select` (projection). An
/// empty `select` object is rejected because it produces no output columns.
pub(in crate::check::shape) fn validate_select_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    validate_from_action(action, action_pointer, "Select", file, diagnostics);
    if let Some(inputs) = get(action, "inputs")
        && as_object(inputs).is_some()
    {
        require_typed_field(
            inputs,
            &pointer_join(action_pointer, "inputs"),
            "select",
            "Select inputs.select must be an object or string",
            file,
            diagnostics,
            |value| as_object(value).is_some() || as_string(value).is_some(),
        );
        if let Some(select) = get(inputs, "select")
            && !is_opaque_arm_expression(file, select)
            && let Some(select_object) = as_object(select)
            && select_object.is_empty()
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-value",
                &file.path,
                pointer_join(&pointer_join(action_pointer, "inputs"), "select"),
                Some(span(select)),
                "Select inputs.select must define at least one mapping",
            ));
        }
    }
}

/// Validate an `Expression` action (date/time helpers). The action-level
/// `kind` selects which fields are required — e.g. AddToTime needs
/// baseTime + interval + timeUnit; ConvertTimeZone needs base plus source
/// and destination zones.
pub(in crate::check::shape) fn validate_expression_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let kind = validate_optional_kind(
        action,
        action_pointer,
        "Expression kind",
        EXPRESSION_KINDS,
        file,
        diagnostics,
    );
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    let Some(kind) = kind else {
        return;
    };
    let inputs_pointer = pointer_join(action_pointer, "inputs");
    if kind.eq_ignore_ascii_case("addtotime") || kind.eq_ignore_ascii_case("subtractfromtime") {
        require_typed_field(
            inputs,
            &inputs_pointer,
            "baseTime",
            "Expression inputs.baseTime must be a string",
            file,
            diagnostics,
            |value| as_string(value).is_some(),
        );
        require_expression_interval_fields(inputs, &inputs_pointer, file, diagnostics);
    } else if kind.eq_ignore_ascii_case("converttimezone") {
        for field in ["baseTime", "sourceTimeZone", "destinationTimeZone"] {
            require_typed_field(
                inputs,
                &inputs_pointer,
                field,
                "Expression time-zone inputs must be strings",
                file,
                diagnostics,
                |value| as_string(value).is_some(),
            );
        }
    } else if kind.eq_ignore_ascii_case("getfuturetime") || kind.eq_ignore_ascii_case("getpasttime")
    {
        require_expression_interval_fields(inputs, &inputs_pointer, file, diagnostics);
    }
}

/// Shared `(interval, timeUnit)` shape used by several Expression kinds.
pub(in crate::check::shape) fn require_expression_interval_fields(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    file: &JsonFile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    require_typed_field(
        inputs,
        inputs_pointer,
        "interval",
        "Expression inputs.interval must be an integer",
        file,
        diagnostics,
        is_integer_value,
    );
    require_typed_field(
        inputs,
        inputs_pointer,
        "timeUnit",
        "Expression inputs.timeUnit must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    validate_optional_string_enum(
        inputs,
        inputs_pointer,
        "timeUnit",
        "Expression inputs.timeUnit",
        TIME_UNITS,
        file,
        diagnostics,
    );
}

/// Validate a `JavaScriptCode` action. Beyond `inputs.code`, the optional
/// `explicitDependencies` block gives the sandbox access to prior actions'
/// outputs — dependencies must (a) already precede this action via
/// runAfter, and (b) not be variable-mutation or loop actions (whose
/// outputs are not first-class in the JS sandbox).
pub(in crate::check::shape) fn validate_javascript_code_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    require_typed_field(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        "code",
        "JavaScriptCode inputs.code must be a string",
        file,
        diagnostics,
        |value| as_string(value).is_some(),
    );
    validate_javascript_explicit_dependencies(
        inputs,
        &pointer_join(action_pointer, "inputs"),
        action_pointer,
        file,
        workflow,
        diagnostics,
    );
}

fn validate_javascript_explicit_dependencies(
    inputs: &json_spanned_value::spanned::Value,
    inputs_pointer: &str,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(dependencies) = get(inputs, "explicitDependencies") else {
        return;
    };
    if is_opaque_arm_expression(file, dependencies) {
        return;
    }
    let dependencies_pointer = pointer_join(inputs_pointer, "explicitDependencies");
    if as_object(dependencies).is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            dependencies_pointer,
            Some(span(dependencies)),
            "JavaScriptCode inputs.explicitDependencies must be an object",
        ));
        return;
    }
    if let Some(actions) = get(dependencies, "actions") {
        let actions_pointer = pointer_join(&dependencies_pointer, "actions");
        if let Some(values) = actions.as_span_array() {
            for (index, action) in values.iter().enumerate() {
                if is_opaque_arm_expression(file, action) {
                    continue;
                }
                if as_string(action).is_none() {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-invalid-type",
                        &file.path,
                        pointer_join(&actions_pointer, &index.to_string()),
                        Some(span(action)),
                        "JavaScriptCode inputs.explicitDependencies.actions entries must be strings",
                    ));
                } else if let Some(action_name) = as_string(action) {
                    if let Some(referenced_action) = workflow.actions.get(action_name) {
                        if !javascript_explicit_dependency_action_supported(referenced_action) {
                            diagnostics.push(Diagnostic::error(
                                "workflow-shape-invalid-context",
                                &file.path,
                                pointer_join(&actions_pointer, &index.to_string()),
                                Some(span(action)),
                                format!(
                                    "JavaScriptCode inputs.explicitDependencies.actions cannot reference action '{action_name}'"
                                ),
                            ));
                        } else if !javascript_explicit_dependency_precedes(
                            workflow,
                            action_pointer,
                            action_name,
                        ) {
                            diagnostics.push(Diagnostic::error(
                                "workflow-shape-invalid-context",
                                &file.path,
                                pointer_join(&actions_pointer, &index.to_string()),
                                Some(span(action)),
                                format!(
                                    "JavaScriptCode inputs.explicitDependencies.actions must reference a preceding action; '{action_name}' is not a runAfter dependency"
                                ),
                            ));
                        }
                    } else {
                        diagnostics.push(Diagnostic::error(
                            "unknown-action-reference",
                            &file.path,
                            pointer_join(&actions_pointer, &index.to_string()),
                            Some(span(action)),
                            format!(
                                "JavaScriptCode inputs.explicitDependencies.actions references missing action '{action_name}'"
                            ),
                        ));
                    }
                }
            }
        } else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                actions_pointer,
                Some(span(actions)),
                "JavaScriptCode inputs.explicitDependencies.actions must be an array",
            ));
        }
    }
    validate_optional_bool_field(
        dependencies,
        &dependencies_pointer,
        "includeTrigger",
        "JavaScriptCode inputs.explicitDependencies.includeTrigger",
        file,
        diagnostics,
    );
}

fn javascript_explicit_dependency_precedes(
    workflow: &Workflow<'_>,
    action_pointer: &str,
    dependency_name: &str,
) -> bool {
    let Some(current_action) = workflow
        .actions
        .values()
        .find(|action| action.pointer == action_pointer)
    else {
        return true;
    };
    let mut stack = current_action
        .run_after
        .iter()
        .map(|dependency| dependency.dependency.as_str())
        .collect::<Vec<_>>();
    for containing_action in workflow
        .actions
        .values()
        .filter(|action| action_contains(action, current_action))
    {
        stack.extend(
            containing_action
                .run_after
                .iter()
                .map(|dependency| dependency.dependency.as_str()),
        );
    }
    let mut visited = std::collections::BTreeSet::new();
    while let Some(candidate) = stack.pop() {
        if javascript_dependency_matches_preceding_action(workflow, candidate, dependency_name) {
            return true;
        }
        if !visited.insert(candidate.to_string()) {
            continue;
        }
        if let Some(action) = workflow.actions.get(candidate) {
            stack.extend(
                action
                    .run_after
                    .iter()
                    .map(|dependency| dependency.dependency.as_str()),
            );
        }
    }
    false
}

fn action_contains(
    candidate: &crate::workflow::ActionInfo,
    action: &crate::workflow::ActionInfo,
) -> bool {
    candidate.pointer != action.pointer
        && action
            .pointer
            .strip_prefix(candidate.pointer.as_str())
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn javascript_dependency_matches_preceding_action(
    workflow: &Workflow<'_>,
    candidate: &str,
    dependency_name: &str,
) -> bool {
    if candidate == dependency_name {
        return true;
    }
    let Some(candidate_action) = workflow.actions.get(candidate) else {
        return false;
    };
    let Some(dependency_action) = workflow.actions.get(dependency_name) else {
        return false;
    };
    action_contains(candidate_action, dependency_action)
}

fn javascript_explicit_dependency_action_supported(action: &crate::workflow::ActionInfo) -> bool {
    !matches!(
        action.kind,
        crate::workflow::ActionKind::Foreach | crate::workflow::ActionKind::Until
    ) && !action
        .action_type
        .as_deref()
        .is_some_and(javascript_explicit_dependency_variable_action)
}

fn javascript_explicit_dependency_variable_action(action_type: &str) -> bool {
    [
        "AppendToArrayVariable",
        "AppendToStringVariable",
        "DecrementVariable",
        "IncrementVariable",
        "InitializeVariable",
        "SetVariable",
    ]
    .iter()
    .any(|candidate| action_type.eq_ignore_ascii_case(candidate))
}

/// Validate a `PowershellCode` action. Only supported in Standard workflows
/// (Consumption / ARM-embedded workflows lack the PowerShell host). Accepts
/// either `codeFile` or its historical `CodeFile` capitalization.
pub(in crate::check::shape) fn validate_powershell_code_action(
    action: &json_spanned_value::spanned::Value,
    action_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if workflow.is_embedded_arm_definition() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(action_pointer, "type"),
            get(action, "type").map(span),
            "PowershellCode actions are supported only in Standard workflows",
        ));
    }

    let Some(inputs) = required_inputs_object(action, action_pointer, file, diagnostics) else {
        return;
    };
    let inputs_pointer = pointer_join(action_pointer, "inputs");
    if get(inputs, "codeFile").is_none() && get(inputs, "CodeFile").is_none() {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(&inputs_pointer, "codeFile"),
            Some(span(inputs)),
            "PowershellCode inputs must define codeFile or CodeFile",
        ));
    }
    validate_optional_string_field(
        inputs,
        &inputs_pointer,
        "codeFile",
        "PowershellCode inputs.codeFile",
        file,
        diagnostics,
    );
    validate_optional_string_field(
        inputs,
        &inputs_pointer,
        "CodeFile",
        "PowershellCode inputs.CodeFile",
        file,
        diagnostics,
    );
}
