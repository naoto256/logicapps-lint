//! Recursive descent over the action tree.
//!
//! Traversal is intentionally flat in its output: nested `Foreach`/`If`/`Scope`/
//! `Switch`/`Until`/`Agent` children are visited but only the top-level
//! [`Workflow::actions`] / [`Workflow::action_list`] indexes are populated. The
//! `depth` field on [`ActionInfo`] preserves the original nesting for rules
//! that care about it.
//!
//! Two entry paths exist per action: `_from_spanned` walks live JSON with
//! source spans; `_from_json` handles the case where a whole subtree was
//! materialized from a static ARM expression and only carries the parent's
//! synthetic span. Both paths must produce the same [`ActionInfo`] shape.

use super::arm_support::{
    arm_null_entry_from_json, arm_null_entry_from_spanned, static_object_from_spanned,
    static_string_from_spanned, unresolved_arm_expression_from_spanned,
};
use super::run_after::{
    has_opaque_run_after_from_json, has_opaque_run_after_from_spanned,
    run_after_dependencies_from_json, run_after_dependencies_from_spanned,
};
use super::variables::{
    initialized_variables_from_json, initialized_variables_from_spanned, variable_target_from_json,
    variable_target_from_spanned, variable_value_from_json, variable_value_from_spanned,
};
use super::*;
use crate::json::{as_object, get, pointer_join, span};
use json_spanned_value::spanned;

/// Entry point: walk a top-level `actions` map at depth 1.
pub(super) fn collect_actions(
    value: Option<&spanned::Value>,
    pointer: &str,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
    workflow: &mut Workflow<'_>,
) {
    collect_actions_at_depth(value, pointer, 1, arm_scope, workflow);
}

fn collect_actions_at_depth(
    value: Option<&spanned::Value>,
    pointer: &str,
    depth: usize,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
    workflow: &mut Workflow<'_>,
) {
    if let Some(object) = value.and_then(as_object) {
        for (name, value) in object.iter() {
            // ARM idiom: entries may be `null` (or an expression evaluating to
            // null) to explicitly opt out of an action — skip rather than
            // record a phantom entry.
            if arm_null_entry_from_spanned(value, arm_scope) {
                continue;
            }
            let action_pointer = pointer_join(pointer, name);
            collect_action_from_spanned(
                name,
                value,
                &action_pointer,
                pointer,
                depth,
                arm_scope,
                workflow,
            );
        }
        return;
    }

    // The container itself may be a fully opaque string like `"[variables('acts')]"`.
    // When it resolves to a static object, cross the ARM boundary once and switch
    // to the serde_json code path — no spans available past this point, so all
    // children share the parent expression's span.
    if let Some((object, source_span)) =
        value.and_then(|value| static_object_from_spanned(value, arm_scope))
    {
        for (name, action) in object {
            if arm_null_entry_from_json(&action) {
                continue;
            }
            let action_pointer = pointer_join(pointer, &name);
            collect_action_from_json(
                &name,
                &action,
                &action_pointer,
                pointer,
                source_span,
                depth,
                workflow,
            );
        }
    }
}

fn collect_action_from_spanned(
    name: &str,
    value: &spanned::Value,
    action_pointer: &str,
    container_pointer: &str,
    depth: usize,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
    workflow: &mut Workflow<'_>,
) {
    if arm_null_entry_from_spanned(value, arm_scope) {
        return;
    }
    if let Some((object, source_span)) = static_object_from_spanned(value, arm_scope) {
        collect_action_from_json(
            name,
            &serde_json::Value::Object(object),
            action_pointer,
            container_pointer,
            source_span,
            depth,
            workflow,
        );
        return;
    }
    // The whole action body may itself be an opaque `[...]` — treat every field
    // as potentially materialized at deploy time so we do not report "missing
    // type", "missing runAfter", etc. on something we simply cannot see.
    let has_opaque_action_entry = unresolved_arm_expression_from_spanned(value, arm_scope);
    let (action_type, has_opaque_type) = action_type_from_spanned(get(value, "type"), arm_scope);
    let kind = ActionKind::from_action_type(action_type.as_deref());
    let action = ActionInfo {
        name: name.to_owned(),
        pointer: action_pointer.to_owned(),
        container_pointer: container_pointer.to_owned(),
        depth,
        action_type: action_type.clone(),
        has_opaque_type: has_opaque_type || has_opaque_action_entry,
        kind,
        run_after: run_after_dependencies_from_spanned(value, action_pointer, arm_scope),
        has_opaque_run_after: has_opaque_run_after_from_spanned(value, arm_scope),
        initialized_variables: initialized_variables_from_spanned(value, arm_scope),
        variable_target: variable_target_from_spanned(value, action_pointer, arm_scope),
        variable_value: variable_value_from_spanned(value, action_pointer, arm_scope),
    };
    insert_action(action, span(value), workflow);
    collect_nested_actions(
        value,
        action_pointer,
        depth,
        kind,
        has_opaque_type || has_opaque_action_entry,
        arm_scope,
        workflow,
    );
}

fn collect_action_from_json(
    name: &str,
    value: &serde_json::Value,
    action_pointer: &str,
    container_pointer: &str,
    source_span: crate::diagnostic::ByteSpan,
    depth: usize,
    workflow: &mut Workflow<'_>,
) {
    if arm_null_entry_from_json(value) {
        return;
    }
    let (action_type, has_opaque_type) = action_type_from_json(value.get("type"));
    let kind = ActionKind::from_action_type(action_type.as_deref());
    let action = ActionInfo {
        name: name.to_owned(),
        pointer: action_pointer.to_owned(),
        container_pointer: container_pointer.to_owned(),
        depth,
        action_type: action_type.clone(),
        has_opaque_type,
        kind,
        run_after: run_after_dependencies_from_json(value, action_pointer, source_span),
        has_opaque_run_after: has_opaque_run_after_from_json(value),
        initialized_variables: initialized_variables_from_json(value),
        variable_target: variable_target_from_json(value, action_pointer, source_span),
        variable_value: variable_value_from_json(value, action_pointer, source_span),
    };
    insert_action(action, source_span, workflow);
    collect_nested_actions_json(
        value,
        action_pointer,
        source_span,
        depth,
        kind,
        has_opaque_type,
        workflow,
    );
}

/// Insert into the primary index and record duplicates.
///
/// Action names are globally unique in Logic Apps, so a repeat name is a shape
/// error the user needs to see. We keep the first sighting in `actions` (so
/// reference resolution stays stable) and push every later declaration to
/// `duplicate_actions`; both are appended to `action_list` in traversal order.
fn insert_action(
    action: ActionInfo,
    action_span: crate::diagnostic::ByteSpan,
    workflow: &mut Workflow<'_>,
) {
    if let Some(first) = workflow.actions.get(&action.name) {
        workflow.duplicate_actions.push(DuplicateAction {
            name: action.name.clone(),
            pointer: action.pointer.clone(),
            first_pointer: first.pointer.clone(),
            span: action_span,
        });
    } else {
        workflow.actions.insert(action.name.clone(), action.clone());
    }
    workflow.action_list.push(action);
}

/// Resolve `type` to a concrete string, or flag it as opaque.
///
/// Returns `(Some(type), false)` when the value is a plain string or an ARM
/// expression that statically evaluates to one; `(None, true)` when it is an
/// ARM expression that cannot be evaluated in the given scope;
/// `(None, false)` when the field is absent or a non-string.
fn action_type_from_spanned(
    value: Option<&spanned::Value>,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> (Option<String>, bool) {
    let Some(value) = value else {
        return (None, false);
    };
    let action_type = static_string_from_spanned(value, arm_scope);
    let has_opaque_type =
        action_type.is_none() && unresolved_arm_expression_from_spanned(value, arm_scope);
    (action_type, has_opaque_type)
}

fn action_type_from_json(value: Option<&serde_json::Value>) -> (Option<String>, bool) {
    let Some(value) = value else {
        return (None, false);
    };
    let Some(text) = value.as_str() else {
        return (None, false);
    };
    if crate::arm::is_full_expression(text) {
        match crate::arm::static_expression_value(text) {
            Some(serde_json::Value::String(action_type)) => (Some(action_type), false),
            Some(_) => (None, false),
            None => (None, true),
        }
    } else {
        (Some(text.to_owned()), false)
    }
}

/// Descend into whichever child-action fields this container kind may host.
///
/// When `has_opaque_type` is set, we do not know which container this is, so
/// speculatively look in every possible field — better to over-index a
/// hypothetical child than to silently drop actions the runtime will execute.
fn collect_nested_actions(
    value: &spanned::Value,
    pointer: &str,
    parent_depth: usize,
    kind: ActionKind,
    has_opaque_type: bool,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
    workflow: &mut Workflow<'_>,
) {
    let child_depth = parent_depth + 1;
    // Logic Apps nests executable actions under a few schema-specific fields.
    // Keep this list explicit so each container shape can be tested separately.
    if has_opaque_type || kind.supports_actions_container() {
        collect_actions_at_depth(
            get(value, "actions"),
            &pointer_join(pointer, "actions"),
            child_depth,
            arm_scope,
            workflow,
        );
    }

    if (has_opaque_type || kind.supports_cases_container())
        && let Some(cases) = get(value, "cases").and_then(as_object)
    {
        let cases_pointer = pointer_join(pointer, "cases");
        for (case_name, case_value) in cases.iter() {
            collect_actions_at_depth(
                get(case_value, "actions"),
                &pointer_join(&pointer_join(&cases_pointer, case_name), "actions"),
                child_depth,
                arm_scope,
                workflow,
            );
        }
    }

    if has_opaque_type || kind.supports_default_container() {
        collect_actions_at_depth(
            get(value, "default").and_then(|v| get(v, "actions")),
            &pointer_join(&pointer_join(pointer, "default"), "actions"),
            child_depth,
            arm_scope,
            workflow,
        );
    }
    if has_opaque_type || kind.supports_else_container() {
        collect_actions_at_depth(
            get(value, "else").and_then(|v| get(v, "actions")),
            &pointer_join(&pointer_join(pointer, "else"), "actions"),
            child_depth,
            arm_scope,
            workflow,
        );
    }

    if (has_opaque_type || kind.supports_tools_container())
        && let Some(tools) = get(value, "tools").and_then(as_object)
    {
        let tools_pointer = pointer_join(pointer, "tools");
        for (tool_name, tool_value) in tools.iter() {
            collect_actions_at_depth(
                get(tool_value, "actions"),
                &pointer_join(&pointer_join(&tools_pointer, tool_name), "actions"),
                child_depth,
                arm_scope,
                workflow,
            );
        }
    }
}

fn collect_nested_actions_json(
    value: &serde_json::Value,
    pointer: &str,
    source_span: crate::diagnostic::ByteSpan,
    parent_depth: usize,
    kind: ActionKind,
    has_opaque_type: bool,
    workflow: &mut Workflow<'_>,
) {
    let child_depth = parent_depth + 1;
    if has_opaque_type || kind.supports_actions_container() {
        collect_json_action_container(
            value.get("actions"),
            &pointer_join(pointer, "actions"),
            source_span,
            child_depth,
            workflow,
        );
    }

    if (has_opaque_type || kind.supports_cases_container())
        && let Some(cases) = value.get("cases").and_then(serde_json::Value::as_object)
    {
        let cases_pointer = pointer_join(pointer, "cases");
        for (case_name, case_value) in cases {
            collect_json_action_container(
                case_value.get("actions"),
                &pointer_join(&pointer_join(&cases_pointer, case_name), "actions"),
                source_span,
                child_depth,
                workflow,
            );
        }
    }

    if has_opaque_type || kind.supports_default_container() {
        collect_json_action_container(
            value.get("default").and_then(|value| value.get("actions")),
            &pointer_join(&pointer_join(pointer, "default"), "actions"),
            source_span,
            child_depth,
            workflow,
        );
    }
    if has_opaque_type || kind.supports_else_container() {
        collect_json_action_container(
            value.get("else").and_then(|value| value.get("actions")),
            &pointer_join(&pointer_join(pointer, "else"), "actions"),
            source_span,
            child_depth,
            workflow,
        );
    }

    if (has_opaque_type || kind.supports_tools_container())
        && let Some(tools) = value.get("tools").and_then(serde_json::Value::as_object)
    {
        let tools_pointer = pointer_join(pointer, "tools");
        for (tool_name, tool_value) in tools {
            collect_json_action_container(
                tool_value.get("actions"),
                &pointer_join(&pointer_join(&tools_pointer, tool_name), "actions"),
                source_span,
                child_depth,
                workflow,
            );
        }
    }
}

/// Descend into an actions container that was materialized from ARM.
///
/// Shared with `extraction` for the case where the root `definition` itself was
/// an opaque expression whose static value we could resolve.
pub(super) fn collect_json_action_container(
    value: Option<&serde_json::Value>,
    pointer: &str,
    source_span: crate::diagnostic::ByteSpan,
    depth: usize,
    workflow: &mut Workflow<'_>,
) {
    let Some(object) = value.and_then(serde_json::Value::as_object) else {
        return;
    };
    for (name, action) in object {
        if arm_null_entry_from_json(action) {
            continue;
        }
        let action_pointer = pointer_join(pointer, name);
        collect_action_from_json(
            name,
            action,
            &action_pointer,
            pointer,
            source_span,
            depth,
            workflow,
        );
    }
}
