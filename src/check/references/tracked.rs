//! `trackedProperties` reference rules.
//!
//! Learn restricts what can appear inside a `trackedProperties` block:
//!   * action trackedProperties: only the current action's inputs/outputs
//!     (via bare `action()` / `outputs('SelfName')` / `body('SelfName')` /
//!     `actions('SelfName')`) and workflow parameters.
//!   * trigger trackedProperties: only the current trigger's inputs/outputs
//!     (via `trigger()` with a whitelisted accessor) and workflow parameters.
//!
//! These are stricter than the rest of WDL: helpers like `workflow()` and
//! `variables()` are always rejected, even though they are legal elsewhere.

use super::run_after::RunAfterIndex;
use crate::json::pointer_join;
use crate::wdl::{
    ReferenceKind, function_call_suffixes_in_string, string_arg_function_call_suffixes_in_string,
    zero_arg_function_call_in_string, zero_arg_function_call_suffixes_in_string,
};
use crate::workflow::Workflow;

#[derive(Clone, Copy, PartialEq, Eq)]
enum TrackedPropertiesSite {
    Action,
    Trigger,
}

/// Gate for function calls inside a trackedProperties block. Returns `true`
/// for calls that are legal in this context (or `true` when the site is not
/// trackedProperties at all, so unrelated sites pass through untouched).
pub(super) fn tracked_properties_function_allowed(
    workflow: &Workflow<'_>,
    run_after: &RunAfterIndex,
    site_pointer: &str,
    site_value: &str,
    call: &crate::wdl::FunctionCall,
) -> bool {
    let Some(site_kind) = tracked_properties_site(workflow, run_after, site_pointer) else {
        // Not a trackedProperties site — general WDL rules apply elsewhere.
        return true;
    };
    // Learn restricts action trackedProperties to current action inputs/outputs
    // and workflow parameters. Trigger/workflow helpers are valid elsewhere but
    // not in this diagnostics projection.
    if site_kind == TrackedPropertiesSite::Action
        && call.name.eq_ignore_ascii_case("action")
        && call.parenthesized
        && zero_arg_function_call_in_string(site_value, "action")
    {
        return tracked_properties_action_access_allowed(site_value);
    }
    if site_kind == TrackedPropertiesSite::Trigger
        && call.name.eq_ignore_ascii_case("trigger")
        && call.parenthesized
        && zero_arg_function_call_in_string(site_value, "trigger")
    {
        return tracked_properties_trigger_access_allowed(site_value);
    }
    if call.name.eq_ignore_ascii_case("actions") {
        return tracked_properties_named_helper_allowed(
            run_after,
            site_pointer,
            site_value,
            "actions",
            true,
        );
    }
    if call.name.eq_ignore_ascii_case("outputs") {
        return tracked_properties_named_helper_allowed(
            run_after,
            site_pointer,
            site_value,
            "outputs",
            false,
        );
    }
    if call.name.eq_ignore_ascii_case("body") {
        return tracked_properties_named_helper_allowed(
            run_after,
            site_pointer,
            site_value,
            "body",
            false,
        );
    }
    // `listCallbackUrl()` never fits — its result is not a static property of
    // the tracked event.
    if call.name.eq_ignore_ascii_case("listCallbackUrl") {
        return false;
    }
    // Explicit blocklist for the remaining helpers. Anything not on the list
    // is accepted — Learn tolerates constants, formatters, `parameters()`, and
    // similar side-effect-free builders in trackedProperties expressions.
    let function = call.name.to_ascii_lowercase();
    match site_kind {
        TrackedPropertiesSite::Action => !matches!(
            function.as_str(),
            "trigger"
                | "triggeroutputs"
                | "triggerbody"
                | "triggerformdatavalue"
                | "triggerformdatamultivalues"
                | "triggermultipartbody"
                | "variables"
                | "workflow"
        ),
        TrackedPropertiesSite::Trigger => !matches!(
            function.as_str(),
            "action" | "actions" | "outputs" | "body" | "variables" | "workflow"
        ),
    }
}

/// For `actions('X')` / `outputs('X')` / `body('X')`: every occurrence in the
/// string must name the current action, and (for `actions(...)`) may only
/// access a whitelisted subset of the action envelope.
fn tracked_properties_named_helper_allowed(
    run_after: &RunAfterIndex,
    site_pointer: &str,
    site_value: &str,
    function_name: &str,
    require_action_accessor: bool,
) -> bool {
    let Some(action) = run_after.containing_action(site_pointer) else {
        return false;
    };
    let all_suffixes = function_call_suffixes_in_string(site_value, function_name);
    let own_suffixes =
        string_arg_function_call_suffixes_in_string(site_value, function_name, &action.name);
    !all_suffixes.is_empty()
        && all_suffixes.len() == own_suffixes.len()
        && (!require_action_accessor
            || own_suffixes
                .iter()
                .all(|suffix| tracked_properties_action_accessor_allowed(suffix)))
}

fn tracked_properties_action_access_allowed(site_value: &str) -> bool {
    let suffixes = zero_arg_function_call_suffixes_in_string(site_value, "action");
    !suffixes.is_empty()
        && suffixes
            .iter()
            .all(|suffix| suffix.is_empty() || tracked_properties_action_accessor_allowed(suffix))
}

fn tracked_properties_trigger_access_allowed(site_value: &str) -> bool {
    let suffixes = zero_arg_function_call_suffixes_in_string(site_value, "trigger");
    !suffixes.is_empty()
        && suffixes
            .iter()
            .all(|suffix| tracked_properties_trigger_accessor_allowed(suffix))
}

fn tracked_properties_action_accessor_allowed(text: &str) -> bool {
    tracked_properties_current_accessor_allowed(text, true)
}

fn tracked_properties_trigger_accessor_allowed(text: &str) -> bool {
    tracked_properties_current_accessor_allowed(text, false)
}

/// Accept `.inputs`/`.outputs` (and bracket variants) unconditionally, and a
/// small set of run-metadata fields (`startTime`, `status`, `trackingId`, ...)
/// when `allow_metadata` is set. Any other trailing accessor is rejected.
fn tracked_properties_current_accessor_allowed(text: &str, allow_metadata: bool) -> bool {
    let compact: String = text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    let input_output_allowed = [
        ".inputs",
        ".outputs",
        "?['inputs']",
        "?['outputs']",
        "['inputs']",
        "['outputs']",
    ]
    .iter()
    .any(|access| {
        compact
            .strip_prefix(access)
            .is_some_and(tracked_properties_accessor_boundary)
    });
    if input_output_allowed {
        return true;
    }
    allow_metadata
        && [
            ".starttime",
            ".endtime",
            ".status",
            ".name",
            ".code",
            ".trackingid",
            ".clienttrackingid",
            "?['starttime']",
            "?['endtime']",
            "?['status']",
            "?['name']",
            "?['code']",
            "?['trackingid']",
            "?['clienttrackingid']",
            "['starttime']",
            "['endtime']",
            "['status']",
            "['name']",
            "['code']",
            "['trackingid']",
            "['clienttrackingid']",
        ]
        .iter()
        .any(|access| {
            compact
                .strip_prefix(access)
                .is_some_and(tracked_properties_accessor_boundary)
        })
}

/// After a whitelisted prefix, the remainder must either be empty or continue
/// with a token boundary — deeper navigation, a comma, or a close paren/brace.
/// Prevents `.inputsExtra` from being mistaken for `.inputs`.
fn tracked_properties_accessor_boundary(rest: &str) -> bool {
    rest.is_empty()
        || rest
            .as_bytes()
            .first()
            .is_some_and(|byte| matches!(byte, b'.' | b'?' | b'[' | b',' | b')' | b'}'))
}

/// Gate for named references (as opposed to function calls) inside a
/// trackedProperties block. The action-scope form allows only self-action
/// references with a whitelisted accessor; parameters are always fine.
pub(super) fn tracked_properties_reference_allowed(
    workflow: &Workflow<'_>,
    run_after: &RunAfterIndex,
    site_pointer: &str,
    site_value: &str,
    reference: &crate::wdl::Reference,
) -> bool {
    let Some(site_kind) = tracked_properties_site(workflow, run_after, site_pointer) else {
        return true;
    };
    // Named references inside action trackedProperties are intentionally narrow:
    // only the current action and workflow parameters are stable there.
    match (site_kind, reference.kind) {
        (TrackedPropertiesSite::Action, ReferenceKind::Action) => {
            run_after.site_references_self_action(site_pointer, &reference.name)
                && tracked_properties_named_action_reference_allowed(site_value, reference)
        }
        (_, ReferenceKind::Parameter) => true,
        _ => false,
    }
}

/// Classify the site: is it under an action's `trackedProperties`, a
/// trigger's `trackedProperties`, or neither?
fn tracked_properties_site(
    workflow: &Workflow<'_>,
    run_after: &RunAfterIndex,
    site_pointer: &str,
) -> Option<TrackedPropertiesSite> {
    if run_after.action_tracked_properties_allowed_at(site_pointer) {
        return Some(TrackedPropertiesSite::Action);
    }
    trigger_tracked_properties_allowed_at(workflow, site_pointer)
        .then_some(TrackedPropertiesSite::Trigger)
}

fn trigger_tracked_properties_allowed_at(workflow: &Workflow<'_>, site_pointer: &str) -> bool {
    let triggers_pointer = pointer_join(&workflow.definition_pointer, "triggers");
    workflow.triggers.iter().any(|trigger| {
        let tracked_pointer = pointer_join(
            &pointer_join(&triggers_pointer, trigger),
            "trackedProperties",
        );
        site_pointer == tracked_pointer
            || site_pointer
                .strip_prefix(&tracked_pointer)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

fn tracked_properties_named_action_reference_allowed(
    site_value: &str,
    reference: &crate::wdl::Reference,
) -> bool {
    let suffixes =
        string_arg_function_call_suffixes_in_string(site_value, "actions", reference.name.as_str());
    suffixes.is_empty()
        || suffixes
            .iter()
            .all(|suffix| tracked_properties_trigger_accessor_allowed(suffix))
}
