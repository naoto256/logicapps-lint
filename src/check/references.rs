//! Reference-resolution diagnostics.
//!
//! `src/wdl/` produces a flat stream of references and function calls found
//! in every WDL-bearing string; `src/workflow/` produces a structural summary
//! of the workflow (action list, run-after edges, triggers, parameters, ...).
//! This module cross-checks the two:
//!
//!   * every action / variable / scoped-action / until / parameter / item /
//!     current-item reference must resolve against the workflow summary,
//!   * action and variable references must additionally be reachable from
//!     their site via the runAfter graph,
//!   * a small set of helpers (`action()`, `listCallbackUrl()`,
//!     `trackedProperties` sub-language) is restricted by site context.
//!
//! The dispatch is a large `match` over `ReferenceKind`; each arm below is
//! commented with the rule it enforces and the diagnostic code it emits.

use crate::diagnostic::Diagnostic;
use crate::json::JsonFile;
use crate::wdl::{
    ReferenceKind, function_calls_in_string, references_in_string, syntax_issues_in_string,
    zero_arg_function_call_in_string,
};
use crate::workflow::{Workflow, run_after_refs, string_sites, string_sites_with_arm_static};
use std::collections::BTreeSet;

mod arm;
mod parameters;
mod run_after;
mod scope;
mod tracked;
mod variables;

use arm::{arm_static_wdl_syntax_check, is_arm_template_expression};
use parameters::{workflow_definition_parameters_dynamic, workflow_definition_static_parameters};
use run_after::RunAfterIndex;
use scope::{
    action_function_allowed_at, action_reference_is_runafter_reachable,
    current_item_reference_is_in_scope, item_reference_is_in_scope, list_callback_url_allowed_at,
    site_is_trigger_site, until_reference_is_in_scope,
};
use tracked::{tracked_properties_function_allowed, tracked_properties_reference_allowed};
use variables::{initialized_variables, variable_reference_is_initialized};

/// ARM context carried alongside every workflow. When the workflow lives
/// inside a deployment template, some strings are ARM expressions rather than
/// WDL and some `parameters` names come from the ARM layer.
pub(super) struct ArmReferenceContext<'a> {
    pub(super) is_deployment_template: bool,
    pub(super) scope: crate::arm::ArmStaticScope<'a>,
}

/// Top-level entry: produce every reference-related diagnostic for a single
/// workflow definition. Callers pass:
///   * `definition` / `definition_pointer` — the JSON subtree to scan,
///   * `workflow` — the parsed structural summary,
///   * `known_parameters` — parameters known from outside the workflow
///     (project defaults, template parameters, etc.),
///   * `project_parameters_dynamic` — set when the project-level parameter
///     set is not statically enumerable, so any name should be tolerated,
///   * `arm` — deployment-template context; drives ARM/WDL boundary rules.
pub(super) fn reference_diagnostics(
    file: &JsonFile,
    definition: &json_spanned_value::spanned::Value,
    definition_pointer: &str,
    workflow: &Workflow<'_>,
    known_parameters: &BTreeSet<String>,
    project_parameters_dynamic: bool,
    arm: ArmReferenceContext<'_>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let variables = initialized_variables(workflow);
    let mut run_after = RunAfterIndex::new(workflow);
    let definition_parameters_dynamic =
        arm.is_deployment_template && workflow_definition_parameters_dynamic(workflow);
    let static_definition_parameters = if arm.is_deployment_template {
        workflow_definition_static_parameters(workflow)
    } else {
        BTreeSet::new()
    };
    // When ARM supplies the whole `definition.parameters` object, the set of
    // valid `parameters('x')` names is deployment-time data rather than WDL data.

    // Structural diagnostics first — they are independent of expression
    // contents and give cleaner errors when the same action name is defined
    // twice.
    for duplicate in &workflow.duplicate_actions {
        diagnostics.push(Diagnostic::error(
            "duplicate-action-name",
            &file.path,
            duplicate.pointer.clone(),
            Some(duplicate.span),
            format!(
                "action '{}' duplicates an action already defined at '{}'",
                duplicate.name, duplicate.first_pointer
            ),
        ));
    }

    // runAfter graph integrity: each edge must name a visible sibling, and
    // the edge must not close a cycle.
    for reference in run_after_refs(workflow) {
        if !run_after.dependency_is_visible(&reference) {
            diagnostics.push(Diagnostic::error(
                "unknown-runafter-reference",
                &file.path,
                reference.pointer,
                Some(reference.span),
                format!(
                    "runAfter references missing sibling action or trigger '{}'",
                    reference.dependency
                ),
            ));
        } else if run_after.creates_cycle(&reference) {
            diagnostics.push(Diagnostic::error(
                "runafter-cycle",
                &file.path,
                reference.pointer,
                Some(reference.span),
                format!(
                    "runAfter creates a cycle between '{}' and '{}'",
                    reference.action, reference.dependency
                ),
            ));
        }
    }

    for action in &workflow.action_list {
        // Variable mutation actions reference variables just as `variables()`
        // does; check the target name and initialization order here because the
        // WDL extractor only sees expression strings.
        let Some(variable_target) = &action.variable_target else {
            continue;
        };
        let variable_name = variable_target.name.as_str();
        let name_pointer = variable_target.pointer.as_str();
        if !variables.contains_key(variable_name) {
            diagnostics.push(Diagnostic::error(
                "unknown-variable-reference",
                &file.path,
                name_pointer.to_owned(),
                Some(variable_target.span),
                format!("variable action targets missing variable '{variable_name}'"),
            ));
        } else if !variable_reference_is_initialized(
            &mut run_after,
            &variables,
            variable_name,
            name_pointer,
        ) {
            diagnostics.push(Diagnostic::error(
                "variable-reference-not-initialized",
                &file.path,
                name_pointer.to_owned(),
                Some(variable_target.span),
                format!(
                    "variable action targets variable '{variable_name}' before its InitializeVariable action is reachable"
                ),
            ));
        }
        if let Some(value) = &action.variable_value
            && value.values.iter().any(|text| {
                references_in_string(text).iter().any(|reference| {
                    reference.kind == ReferenceKind::Variable && reference.name == variable_name
                })
            })
        {
            diagnostics.push(Diagnostic::error(
                "variable-self-reference",
                &file.path,
                value.pointer.clone(),
                Some(value.span),
                format!("SetVariable cannot update variable '{variable_name}' from its own current value"),
            ));
        }
    }

    // Collect every string site to inspect. In an ARM deployment template we
    // additionally expose fragments produced by static ARM evaluation so that
    // ARM-materialized WDL gets checked as well.
    let sites = if arm.is_deployment_template {
        string_sites_with_arm_static(definition, definition_pointer, arm.scope)
    } else {
        string_sites(definition, definition_pointer)
    };

    for site in sites {
        let site_value = site.value.as_ref();
        // Skip authored ARM expressions, but still scan strings produced by
        // static ARM evaluation because those are deployed WDL payloads.
        if arm.is_deployment_template && !site.arm_static && is_arm_template_expression(site_value)
        {
            continue;
        }
        {
            // Every WDL reference or interpolation begins with `@`; strings
            // without one cannot contain WDL to check.
            if !site_value.contains('@') {
                continue;
            }
            // An ARM-static fragment that opens with `@` and could still grow
            // to its left may or may not be WDL — defer WDL parsing until the
            // full text is available. Syntax check still runs above.
            let left_ambiguous_wdl_start = site.arm_static
                && site.arm_partial
                && site.arm_partial_can_extend_left
                && site_value.starts_with('@');
            if !site.arm_static
                || !site.arm_partial
                || arm_static_wdl_syntax_check(site_value, site.arm_partial_can_extend_right)
            {
                // Static ARM fragments are syntax-checked only if they look
                // like WDL; arbitrary ARM string literals may just be payload text.
                for issue in syntax_issues_in_string(site_value) {
                    diagnostics.push(Diagnostic::error(
                        "wdl-syntax-error",
                        &file.path,
                        site.pointer.clone(),
                        Some(site.span),
                        issue.message,
                    ));
                }
            }

            if left_ambiguous_wdl_start {
                continue;
            }

            for call in function_calls_in_string(site_value) {
                // Context-only checks run before name resolution because some
                // invalid helpers, such as `workflow()` in trackedProperties, do
                // not carry a named reference to resolve.
                if !tracked_properties_function_allowed(
                    workflow,
                    &run_after,
                    &site.pointer,
                    site_value,
                    &call,
                ) {
                    diagnostics.push(Diagnostic::error(
                        "wdl-invalid-context",
                        &file.path,
                        site.pointer.clone(),
                        Some(site.span),
                        "trackedProperties can only reference this site's own action or trigger and workflow parameters; \
                         an action's trackedProperties cannot reference the trigger, and vice versa",
                    ));
                } else if call.name.eq_ignore_ascii_case("action")
                    && call.parenthesized
                    && zero_arg_function_call_in_string(site_value, "action")
                    && !action_function_allowed_at(workflow, &run_after, &site.pointer)
                {
                    diagnostics.push(Diagnostic::error(
                        "wdl-invalid-context",
                        &file.path,
                        site.pointer.clone(),
                        Some(site.span),
                        "WDL action() is only supported in trackedProperties, webhook unsubscribe, or Until expressions",
                    ));
                } else if call.name.eq_ignore_ascii_case("listCallbackUrl")
                    && !list_callback_url_allowed_at(workflow, &site.pointer)
                {
                    diagnostics.push(Diagnostic::error(
                        "wdl-invalid-context",
                        &file.path,
                        site.pointer.clone(),
                        Some(site.span),
                        "WDL listCallbackUrl() is only supported in webhook actions or triggers",
                    ));
                }
            }

            for reference in references_in_string(site_value) {
                // trackedProperties has a stricter reference language than the
                // rest of WDL; reject out-of-context helpers before runAfter checks.
                if !tracked_properties_reference_allowed(
                    workflow,
                    &run_after,
                    &site.pointer,
                    site_value,
                    &reference,
                ) {
                    diagnostics.push(Diagnostic::error(
                        "wdl-invalid-context",
                        &file.path,
                        site.pointer.clone(),
                        Some(site.span),
                        "trackedProperties can only reference this site's own action or trigger and workflow parameters; \
                         an action's trackedProperties cannot reference the trigger, and vice versa",
                    ));
                    continue;
                }
                match reference.kind {
                    ReferenceKind::Action => {
                        // Three-tier check: does the action exist? Are we at
                        // a trigger site (where actions are unusable)? Does
                        // the runAfter graph reach it? A self-reference is
                        // recognised specially so trackedProperties can allow
                        // `outputs('Self')` without a runAfter cycle.
                        if !workflow.actions.contains_key(&reference.name) {
                            diagnostics.push(Diagnostic::error(
                                "unknown-action-reference",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "WDL expression references missing action '{}'",
                                    reference.name
                                ),
                            ));
                        } else if site_is_trigger_site(definition_pointer, &site.pointer) {
                            diagnostics.push(Diagnostic::error(
                                "action-reference-not-runafter",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "trigger expression references action '{}' before actions run",
                                    reference.name
                                ),
                            ));
                        } else if run_after
                            .site_references_self_action(&site.pointer, &reference.name)
                        {
                            if !run_after.action_tracked_properties_allowed_at(&site.pointer) {
                                diagnostics.push(Diagnostic::error(
                                    "action-reference-not-runafter",
                                    &file.path,
                                    site.pointer.clone(),
                                    Some(site.span),
                                    format!(
                                        "WDL expression references action '{}' without a runAfter dependency path",
                                        reference.name
                                    ),
                                ));
                            }
                        } else if !action_reference_is_runafter_reachable(
                            &mut run_after,
                            &reference.name,
                            &site.pointer,
                        ) {
                            // Non-self action references need an explicit or
                            // inherited runAfter path before outputs are safe to read.
                            diagnostics.push(Diagnostic::error(
                                "action-reference-not-runafter",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "WDL expression references action '{}' without a runAfter dependency path",
                                    reference.name
                                ),
                            ));
                        }
                    }
                    ReferenceKind::CurrentItem => {
                        // Bare `item()` — legal inside foreach bodies and the
                        // per-row field of certain data operations.
                        if !current_item_reference_is_in_scope(workflow, &site.pointer) {
                            diagnostics.push(Diagnostic::error(
                                "item-out-of-scope",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                "WDL expression uses item() outside a Foreach action or per-item data operation field"
                                    .to_owned(),
                            ));
                        }
                    }
                    ReferenceKind::ScopedAction => {
                        // `result('Scope')` — target must be a scope-like
                        // action (Scope/If/Switch) with an aggregate result,
                        // and, like plain action references, must be
                        // runAfter-reachable and not sit at a trigger site.
                        if !workflow.action_list.iter().any(|action| {
                            action.name == reference.name
                                && (action.kind.supports_result() || action.has_opaque_type)
                        }) {
                            diagnostics.push(Diagnostic::error(
                                "unknown-scoped-action-reference",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "WDL expression references missing scoped action '{}'",
                                    reference.name
                                ),
                            ));
                        } else if site_is_trigger_site(definition_pointer, &site.pointer) {
                            diagnostics.push(Diagnostic::error(
                                "action-reference-not-runafter",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "trigger expression references scoped action '{}' before actions run",
                                    reference.name
                                ),
                            ));
                        } else if !action_reference_is_runafter_reachable(
                            &mut run_after,
                            &reference.name,
                            &site.pointer,
                        ) {
                            diagnostics.push(Diagnostic::error(
                                "action-reference-not-runafter",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "WDL expression references scoped action '{}' without a runAfter dependency path",
                                    reference.name
                                ),
                            ));
                        }
                    }
                    ReferenceKind::UntilLoop => {
                        // Until-loop metadata (`iterationIndexes(...)` etc.):
                        // only usable inside the loop body or its expression.
                        if !until_reference_is_in_scope(workflow, &reference.name, &site.pointer) {
                            diagnostics.push(Diagnostic::error(
                                "unknown-until-reference",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "WDL expression references missing or out-of-scope Until action '{}'",
                                    reference.name
                                ),
                            ));
                        }
                    }
                    ReferenceKind::Variable => {
                        // Variables are top-level only and must be reachable
                        // via runAfter from at least one initializer.
                        // Trigger sites cannot see variables at all, since
                        // triggers evaluate before any action runs.
                        if !variables.contains_key(&reference.name) {
                            diagnostics.push(Diagnostic::error(
                                "unknown-variable-reference",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "WDL expression references missing variable '{}'",
                                    reference.name
                                ),
                            ));
                        } else if site_is_trigger_site(definition_pointer, &site.pointer) {
                            diagnostics.push(Diagnostic::error(
                                "variable-reference-not-initialized",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "trigger expression references variable '{}' before actions run",
                                    reference.name
                                ),
                            ));
                        } else if !variable_reference_is_initialized(
                            &mut run_after,
                            &variables,
                            &reference.name,
                            &site.pointer,
                        ) {
                            diagnostics.push(Diagnostic::error(
                                "variable-reference-not-initialized",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "WDL expression references variable '{}' before its InitializeVariable action is reachable",
                                    reference.name
                                ),
                            ));
                        }
                    }
                    ReferenceKind::Parameter => {
                        // Accept the name if any source can supply it: the
                        // project-level parameter set is dynamic, ARM
                        // supplies parameters dynamically, or the name is
                        // present in one of the known-static sets.
                        if !project_parameters_dynamic
                            && !definition_parameters_dynamic
                            && !workflow.parameters.contains(&reference.name)
                            && !static_definition_parameters.contains(&reference.name)
                            && !known_parameters.contains(&reference.name)
                        {
                            diagnostics.push(Diagnostic::error(
                                "project-missing-definition-parameter",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "WDL expression references missing parameter '{}'",
                                    reference.name
                                ),
                            ));
                        }
                    }
                    ReferenceKind::Item => {
                        // `items('Loop')` — target must be a foreach-shaped
                        // action AND the site must live inside its body.
                        // Both failures cascade to the same diagnostic code
                        // because both are "the loop name is not in scope
                        // here" from a user perspective.
                        let foreach_exists = workflow.action_list.iter().any(|action| {
                            action.name == reference.name
                                && (action.kind.supports_items() || action.has_opaque_type)
                        });
                        if !foreach_exists {
                            diagnostics.push(Diagnostic::error(
                                "unknown-foreach-reference",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "WDL expression references missing Foreach action '{}'",
                                    reference.name
                                ),
                            ));
                        } else if !item_reference_is_in_scope(
                            workflow,
                            &reference.name,
                            &site.pointer,
                        ) {
                            diagnostics.push(Diagnostic::error(
                                "unknown-foreach-reference",
                                &file.path,
                                site.pointer.clone(),
                                Some(site.span),
                                format!(
                                    "WDL expression references Foreach action '{}' outside its actions scope",
                                    reference.name
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    diagnostics
}
