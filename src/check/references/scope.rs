//! Structural scoping predicates.
//!
//! WDL references are legal or not based on where a string lives in the JSON
//! tree relative to certain actions and triggers. This module reduces those
//! rules to pointer-prefix questions plus a runAfter reachability climb.

use super::run_after::RunAfterIndex;
use crate::json::{as_string, get, pointer_join};
use crate::workflow::{ActionKind, Workflow};

/// A trigger site is anything inside `<definition>/triggers/...`. Trigger
/// expressions run before any action, so they may never resolve action or
/// variable references.
pub(super) fn site_is_trigger_site(definition_pointer: &str, site_pointer: &str) -> bool {
    let triggers_pointer = pointer_join(definition_pointer, "triggers");
    site_pointer == triggers_pointer
        || site_pointer
            .strip_prefix(&triggers_pointer)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Whether an action reference at `site_pointer` is satisfied by the runAfter
/// graph. Walks from the innermost containing action outward: if any level in
/// the ancestry can reach the target, the reference is legal at this site.
pub(super) fn action_reference_is_runafter_reachable(
    run_after: &mut RunAfterIndex,
    reference_name: &str,
    site_pointer: &str,
) -> bool {
    let Some(mut action) = run_after.containing_action(site_pointer) else {
        // Site outside any action (top-level outputs, etc.) — no runAfter
        // constraints apply.
        return true;
    };

    loop {
        // If the current path already has an unresolved runAfter edge, avoid
        // cascading dependency diagnostics from a graph we know is incomplete.
        if run_after.has_unresolved_run_after(&action) {
            return true;
        }
        // Special case: inside an Until action's `expression`, references to
        // actions in the loop body are legal even though the body has not run
        // by the time the expression is first evaluated on entry — the
        // expression is re-evaluated after each iteration.
        if action_may_be_kind(&action, ActionKind::Until)
            && run_after.action_covers_reference(&action, reference_name)
            && site_is_action_field(&action.pointer, site_pointer, "expression")
        {
            return true;
        }
        if run_after.reaches_action(&action.container_pointer, &action.name, reference_name) {
            return true;
        }
        // Climb into the parent scope. A nested site can validly reference an
        // action that runs before its outer scope even if the outer scope
        // itself has no runAfter tie to it inside this container.
        let Some(parent) = run_after.parent_action(&action) else {
            return false;
        };
        action = parent;
    }
}

fn containing_action<'a>(
    workflow: &'a Workflow<'_>,
    site_pointer: &str,
) -> Option<&'a crate::workflow::ActionInfo> {
    workflow
        .action_list
        .iter()
        .filter(|action| {
            site_pointer == action.pointer
                || site_pointer.starts_with(&format!("{}/", action.pointer))
        })
        .max_by_key(|action| action.pointer.len())
}

/// True if `items('loop_name')` is legal at the site — the named loop must
/// exist and the site must live inside its `actions` block.
pub(super) fn item_reference_is_in_scope(
    workflow: &Workflow<'_>,
    loop_name: &str,
    site_pointer: &str,
) -> bool {
    workflow.action_list.iter().any(|action| {
        action.name == loop_name
            && action_may_support_items(action)
            && site_is_inside_action_actions(action, site_pointer)
    })
}

/// True if a bare `item()` call is legal at the site. Allowed inside any
/// current-item-supporting action's body, plus a narrow set of data operation
/// per-row fields.
pub(super) fn current_item_reference_is_in_scope(
    workflow: &Workflow<'_>,
    site_pointer: &str,
) -> bool {
    workflow.action_list.iter().any(|action| {
        if !action_may_support_current_item(action) {
            return false;
        }
        if action.has_opaque_type {
            return site_is_inside_action_actions(action, site_pointer);
        }
        if action.kind == ActionKind::DataOperation {
            return data_operation_current_item_allowed_at(workflow, action, site_pointer);
        }
        site_is_inside_action_actions(action, site_pointer)
    })
}

fn data_operation_current_item_allowed_at(
    workflow: &Workflow<'_>,
    action: &crate::workflow::ActionInfo,
    site_pointer: &str,
) -> bool {
    if !site_is_inside_action(action, site_pointer) {
        return false;
    }
    let Some(action_type) = workflow
        .node_at(&action.pointer)
        .and_then(|value| get(value, "type"))
        .and_then(as_string)
        .or(action.action_type.as_deref())
    else {
        return false;
    };
    let inputs_pointer = pointer_join(&action.pointer, "inputs");
    // Data operations expose `item()` only in the projection/predicate field
    // that iterates rows; using it in `from` would read before iteration starts.
    let allowed_pointer = if action_type.eq_ignore_ascii_case("query") {
        pointer_join(&inputs_pointer, "where")
    } else if action_type.eq_ignore_ascii_case("select") {
        pointer_join(&inputs_pointer, "select")
    } else if action_type.eq_ignore_ascii_case("table") {
        pointer_join(&inputs_pointer, "columns")
    } else {
        return false;
    };
    site_pointer == allowed_pointer || site_pointer.starts_with(&format!("{allowed_pointer}/"))
}

/// True if referring to an Until action's outputs is legal at the site — the
/// site must be either inside the loop body or the loop's own `expression`.
pub(super) fn until_reference_is_in_scope(
    workflow: &Workflow<'_>,
    loop_name: &str,
    site_pointer: &str,
) -> bool {
    workflow.action_list.iter().any(|action| {
        action.name == loop_name
            && action_may_be_kind(action, ActionKind::Until)
            && (site_pointer == pointer_join(&action.pointer, "expression")
                || site_is_inside_action_actions(action, site_pointer))
    })
}

// Opaque-typed actions match every predicate below: without a concrete kind
// we cannot prove a rule is violated, so we prefer under-reporting to noise.

fn action_may_be_kind(action: &crate::workflow::ActionInfo, kind: ActionKind) -> bool {
    action.kind == kind || action.has_opaque_type
}

fn action_may_support_items(action: &crate::workflow::ActionInfo) -> bool {
    action.kind.supports_items() || action.has_opaque_type
}

fn action_may_support_current_item(action: &crate::workflow::ActionInfo) -> bool {
    action.kind.supports_current_item() || action.has_opaque_type
}

fn site_is_inside_action_actions(action: &crate::workflow::ActionInfo, site_pointer: &str) -> bool {
    site_pointer.starts_with(&format!("{}/actions/", action.pointer))
}

fn site_is_action_field(action_pointer: &str, site_pointer: &str, field: &str) -> bool {
    let field_pointer = pointer_join(action_pointer, field);
    site_pointer == field_pointer || site_pointer.starts_with(&format!("{field_pointer}/"))
}

fn site_is_inside_action(action: &crate::workflow::ActionInfo, site_pointer: &str) -> bool {
    site_pointer == action.pointer
        || site_pointer
            .strip_prefix(&action.pointer)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn site_is_inside_action_pointer(
    action_pointer: &str,
    site_pointer: &str,
    relative_path: &str,
) -> bool {
    let base = format!("{action_pointer}/{relative_path}");
    site_pointer == base || site_pointer.starts_with(&format!("{base}/"))
}

/// Whether a zero-arg `action()` call is legal at the site. Only three
/// contexts qualify: trackedProperties, a webhook action's `inputs/unsubscribe`
/// payload (where `action()` refers to the subscribe call), and the
/// `expression` of an Until action.
pub(super) fn action_function_allowed_at(
    workflow: &Workflow<'_>,
    run_after: &RunAfterIndex,
    site_pointer: &str,
) -> bool {
    if run_after.action_tracked_properties_allowed_at(site_pointer) {
        return true;
    }
    if containing_action(workflow, site_pointer).is_some_and(|action| {
        site_is_inside_action_pointer(&action.pointer, site_pointer, "inputs/unsubscribe")
    }) {
        return containing_action_type_match(
            workflow,
            site_pointer,
            &["ApiConnectionWebhook", "HttpWebhook"],
        )
        .may_match();
    }
    containing_action(workflow, site_pointer).is_some_and(|action| {
        action_may_be_kind(action, ActionKind::Until)
            && site_pointer == pointer_join(&action.pointer, "expression")
    })
}

/// `listCallbackUrl()` is only meaningful in webhook actions and webhook
/// triggers — anywhere else there is no callback endpoint to fetch.
pub(super) fn list_callback_url_allowed_at(workflow: &Workflow<'_>, site_pointer: &str) -> bool {
    containing_action_type_match(
        workflow,
        site_pointer,
        &["ApiConnectionWebhook", "HttpWebhook"],
    )
    .may_match()
        || containing_trigger_type_match(
            workflow,
            site_pointer,
            &["ApiConnectionWebhook", "HttpWebhook"],
        )
        .may_match()
}

/// Result of comparing a container's declared type against an expected set.
/// `Opaque` means the type is not statically known (ARM-supplied); such cases
/// are treated as possible matches to avoid spurious diagnostics.
#[derive(Clone, Copy)]
enum TypeMatch {
    Matches,
    Differs,
    Opaque,
}

impl TypeMatch {
    fn may_match(self) -> bool {
        !matches!(self, Self::Differs)
    }
}

fn containing_action_type_match(
    workflow: &Workflow<'_>,
    site_pointer: &str,
    action_types: &[&str],
) -> TypeMatch {
    let Some(action) = containing_action(workflow, site_pointer) else {
        return TypeMatch::Differs;
    };
    if action.has_opaque_type {
        return TypeMatch::Opaque;
    }
    match action.action_type.as_deref() {
        Some(action_type)
            if action_types
                .iter()
                .any(|expected| action_type.eq_ignore_ascii_case(expected)) =>
        {
            TypeMatch::Matches
        }
        _ => TypeMatch::Differs,
    }
}

fn containing_trigger_type_match(
    workflow: &Workflow<'_>,
    site_pointer: &str,
    trigger_types: &[&str],
) -> TypeMatch {
    let triggers_pointer = pointer_join(&workflow.definition_pointer, "triggers");
    let Some(trigger_name) = workflow.triggers.iter().find(|trigger_name| {
        let trigger_pointer = pointer_join(&triggers_pointer, trigger_name);
        site_pointer == trigger_pointer || site_pointer.starts_with(&format!("{trigger_pointer}/"))
    }) else {
        return TypeMatch::Differs;
    };
    if workflow.triggers_with_opaque_type.contains(trigger_name) {
        return TypeMatch::Opaque;
    }
    match workflow.trigger_types.get(trigger_name) {
        Some(trigger_type)
            if trigger_types
                .iter()
                .any(|expected| trigger_type.eq_ignore_ascii_case(expected)) =>
        {
            TypeMatch::Matches
        }
        _ => TypeMatch::Differs,
    }
}
