//! Variable initialization tracking.
//!
//! A workflow variable is defined by a top-level `InitializeVariable` action.
//! A reference to `variables('name')` is only valid at a site whose runAfter
//! ancestry can reach one such initializer. Nested initializers (inside a
//! scope, foreach, etc.) do not create workflow-scope variables.

use super::run_after::RunAfterIndex;
use super::scope::action_reference_is_runafter_reachable;
use crate::json::pointer_join;
use std::collections::BTreeMap;

/// Map variable name -> names of top-level actions that initialize it. A
/// variable may have multiple initializers on parallel branches; any one of
/// them reaching the site is sufficient.
pub(super) fn initialized_variables(
    workflow: &crate::workflow::Workflow<'_>,
) -> BTreeMap<String, Vec<String>> {
    let mut variables: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let top_level_actions = pointer_join(&workflow.definition_pointer, "actions");

    for action in &workflow.action_list {
        // Only top-level InitializeVariable actions create workflow variables;
        // nested ones inside scopes are ignored by the runtime.
        if action.container_pointer != top_level_actions {
            continue;
        }
        for variable in &action.initialized_variables {
            variables
                .entry(variable.name.clone())
                .or_default()
                .push(action.name.clone());
        }
    }

    variables
}

/// True if at least one `InitializeVariable` for `variable_name` is
/// runAfter-reachable from `site_pointer`.
pub(super) fn variable_reference_is_initialized(
    run_after: &mut RunAfterIndex,
    variables: &BTreeMap<String, Vec<String>>,
    variable_name: &str,
    site_pointer: &str,
) -> bool {
    let Some(initializers) = variables.get(variable_name) else {
        return false;
    };
    // A site outside any action (e.g. workflow-level outputs) has no runAfter
    // constraints — every declared variable is considered visible there.
    if run_after.containing_action(site_pointer).is_none() {
        return true;
    }
    initializers.iter().any(|initializer| {
        action_reference_is_runafter_reachable(run_after, initializer, site_pointer)
    })
}
