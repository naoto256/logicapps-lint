//! Top-level orchestration for building a [`Workflow`] summary.
//!
//! Handles the split between "definition is live JSON" (normal case) and
//! "definition is itself an opaque ARM expression that materializes to an
//! object" (ARM-embedded case). In the second case we lose per-leaf spans and
//! fall back to the `serde_json` code paths for everything below the root.

use super::actions::{collect_actions, collect_json_action_container};
use super::arm_support::static_object_from_spanned;
use super::parameters::{collect_parameters, collect_parameters_json};
use super::triggers::{collect_triggers, collect_triggers_json};
use super::*;
use crate::json::{get, pointer_join};
use std::collections::{BTreeMap, BTreeSet};

/// Shared body of the two public extractors on the parent module.
/// `arm_scope = None` produces a scope-free summary; `Some(scope)` enables
/// static ARM materialization and opaque-hole tracking.
pub(super) fn extract_definition_inner<'a>(
    definition: &'a spanned::Value,
    definition_pointer: &str,
    kind: Option<WorkflowKind>,
    arm_scope: Option<crate::arm::ArmStaticScope<'_>>,
) -> Workflow<'a> {
    // Build a shallow graph index for reference checks. Shape validation still
    // reads the original JSON; this pass only records names, containers, and spans.
    let mut workflow = Workflow {
        definition,
        definition_pointer: definition_pointer.to_owned(),
        kind,
        actions: BTreeMap::new(),
        action_list: Vec::new(),
        duplicate_actions: Vec::new(),
        triggers: BTreeSet::new(),
        trigger_types: BTreeMap::new(),
        triggers_with_opaque_type: BTreeSet::new(),
        triggers_with_split_on: BTreeSet::new(),
        triggers_with_recurrence: BTreeSet::new(),
        parameters: BTreeSet::new(),
    };

    // ARM boundary: if the entire definition is an opaque expression that
    // resolves to an object (e.g. `[parameters('def')]`), walk the materialized
    // JSON with the wrapper's span shared across every child site.
    if let Some((static_definition, source_span)) =
        static_object_from_spanned(definition, arm_scope)
    {
        let static_definition = serde_json::Value::Object(static_definition);
        collect_triggers_json(
            static_definition.get("triggers"),
            &pointer_join(definition_pointer, "triggers"),
            &mut workflow,
        );
        collect_json_action_container(
            static_definition.get("actions"),
            &pointer_join(definition_pointer, "actions"),
            source_span,
            1,
            &mut workflow,
        );
        collect_parameters_json(
            static_definition.get("parameters"),
            &mut workflow.parameters,
        );
        return workflow;
    }

    collect_triggers(
        get(definition, "triggers"),
        &pointer_join(definition_pointer, "triggers"),
        arm_scope,
        &mut workflow,
    );

    collect_actions(
        get(definition, "actions"),
        &pointer_join(definition_pointer, "actions"),
        arm_scope,
        &mut workflow,
    );
    collect_parameters(
        get(definition, "parameters"),
        arm_scope,
        &mut workflow.parameters,
    );
    workflow
}
