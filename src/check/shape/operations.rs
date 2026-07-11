//! Driver that walks the `triggers` and `actions` containers, dispatches each
//! entry to its per-type spec, and re-runs the same specs on ARM-materialized
//! views so opaque expressions still receive diagnostics.
//!
//! Two parallel worlds:
//!   * The **spanned** path (`collect_trigger_shape`, `collect_action_container_shape`)
//!     operates on the raw parsed JSON with source spans intact.
//!   * The **materialized** path (`collect_json_*`, `validate_materialized_json_*`)
//!     runs after ARM has resolved values into a serde_json tree; because those
//!     values have no source location, diagnostics are rebound to the original
//!     ARM expression's span via `extend_materialized_diagnostics`.
//!
//! For each entry, the driver validates the type field, dispatches to
//! `registry::action_spec` / `registry::trigger_spec`, then recurses into the
//! action containers the type supports (`actions`, `cases`, `default`, `else`,
//! `tools`) — with `child_has_opaque_type` widening acceptance when the child's
//! type cannot be statically resolved.

use super::limits::*;
use super::materialized::*;
use super::*;
use crate::json::to_json_value;

/// Walk `triggers`, validating each trigger entry and its common fields.
pub(super) fn collect_trigger_shape(
    value: Option<&json_spanned_value::spanned::Value>,
    pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = value else {
        return;
    };
    if arm_optional_property_absent(file, value) {
        return;
    }
    // Whole `triggers` object is an ARM expression: try to resolve it and
    // dispatch to the materialized-JSON walker so diagnostics still land.
    if is_opaque_arm_expression(file, value) {
        if let Some((value, source_span)) = static_json_value_from_spanned(file, value) {
            if let Some(triggers) = value.as_object() {
                collect_json_trigger_shape(
                    triggers,
                    pointer,
                    file,
                    workflow,
                    source_span,
                    diagnostics,
                );
            } else {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-type",
                    &file.path,
                    pointer.to_owned(),
                    Some(source_span),
                    "triggers must be an object",
                ));
            }
        }
        return;
    }
    let Some(triggers) = as_object(value) else {
        return;
    };

    for (name, trigger) in triggers.iter() {
        if arm_optional_property_absent(file, trigger) {
            continue;
        }
        let trigger_pointer = pointer_join(pointer, name);
        validate_operation_name_length(
            name,
            &trigger_pointer,
            "trigger",
            file,
            Some(span(trigger)),
            diagnostics,
        );
        if is_opaque_arm_expression(file, trigger) {
            // ARM can provide the whole trigger entry object.
            if let Some((trigger_value, source_span)) =
                static_json_value_from_spanned(file, trigger)
            {
                if trigger_value.is_object() {
                    validate_json_trigger_shape(
                        &trigger_value,
                        &trigger_pointer,
                        file,
                        workflow,
                        source_span,
                        diagnostics,
                    );
                } else {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-invalid-type",
                        &file.path,
                        trigger_pointer,
                        Some(source_span),
                        "trigger entries must be objects",
                    ));
                }
            }
            continue;
        }
        let Some(_trigger_object) = as_object(trigger) else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                trigger_pointer,
                Some(span(trigger)),
                "trigger entries must be objects",
            ));
            continue;
        };

        let Some(trigger_type_value) = get(trigger, "type") else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-missing-field",
                &file.path,
                pointer_join(&trigger_pointer, "type"),
                Some(span(trigger)),
                "trigger is missing required field 'type'",
            ));
            continue;
        };
        let Some(trigger_type) = static_string_from_spanned(file, trigger_type_value) else {
            if unresolved_arm_expression_from_spanned(file, trigger_type_value) {
                let site = Site::trigger(trigger, trigger_pointer);
                let mut ctx = ShapeCtx::new(file, workflow, arm_scope, diagnostics);
                common::validate_type_independent_common_fields(&mut ctx, &site, "trigger");
                triggers::validate_trigger_common_fields(
                    site.value,
                    &site.pointer,
                    ctx.file,
                    ctx.diagnostics,
                );
            } else if is_opaque_arm_expression(file, trigger_type_value)
                || as_string(trigger_type_value).is_none()
            {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-type",
                    &file.path,
                    pointer_join(&trigger_pointer, "type"),
                    Some(span(trigger_type_value)),
                    "trigger type must be a string",
                ));
            } else {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-missing-field",
                    &file.path,
                    pointer_join(&trigger_pointer, "type"),
                    Some(span(trigger)),
                    "trigger is missing required field 'type'",
                ));
            }
            continue;
        };

        let Some(spec) = registry::trigger_spec(&trigger_type) else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-unknown-type",
                &file.path,
                pointer_join(&trigger_pointer, "type"),
                get(trigger, "type").map(span),
                format!("unknown trigger type '{trigger_type}'"),
            ));
            continue;
        };
        if !registry::known_trigger_type(&trigger_type) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-unknown-type",
                &file.path,
                pointer_join(&trigger_pointer, "type"),
                get(trigger, "type").map(span),
                format!("unknown trigger type '{trigger_type}'"),
            ));
            continue;
        }
        validate_trigger_workflow_context(
            &trigger_type,
            &trigger_pointer,
            file,
            workflow,
            get(trigger, "type").map(span),
            get(trigger, "recurrence").is_some(),
            diagnostics,
        );

        let site = Site::trigger(trigger, trigger_pointer);
        let mut ctx = ShapeCtx::new(file, workflow, arm_scope, diagnostics);
        if validate_with_scoped_trigger_fields(&mut ctx, &site, spec) {
            triggers::validate_trigger_common_fields(
                site.value,
                &site.pointer,
                ctx.file,
                ctx.diagnostics,
            );
            continue;
        }
        spec.validate(&mut ctx, &site);
        common::validate_common_fields(&mut ctx, &site, "trigger");
        triggers::validate_trigger_common_fields(
            site.value,
            &site.pointer,
            ctx.file,
            ctx.diagnostics,
        );
    }
}

/// Second-pass trigger validation for the case where `inputs` or `recurrence`
/// contains ARM expressions we *can* statically materialize.
///
/// We rebuild the trigger object with the materialized fields swapped in, run
/// the spec against that ghost value, and then re-anchor any diagnostics to the
/// original ARM span so the user sees the error at the authored location.
/// Returns true iff materialization actually replaced something (nothing to do
/// otherwise).
fn validate_with_scoped_trigger_fields(
    ctx: &mut ShapeCtx<'_, '_, '_>,
    site: &Site<'_>,
    spec: &registry::TriggerSpec,
) -> bool {
    let Some(mut trigger) = to_json_value(site.value).and_then(|value| match value {
        serde_json::Value::Object(object) => Some(object),
        _ => None,
    }) else {
        return false;
    };

    let mut source_span = None;
    for field in ["inputs", "recurrence"] {
        let Some(value) = get(site.value, field) else {
            continue;
        };
        let Some((materialized, field_span)) = materialized_trigger_field_value(ctx, value) else {
            continue;
        };
        source_span.get_or_insert(field_span);
        if materialized.is_null() {
            trigger.remove(field);
        } else {
            trigger.insert(field.to_owned(), materialized);
        }
    }
    let Some(source_span) = source_span else {
        return false;
    };

    let Some(materialized_trigger) = spanned_value_from_json(&serde_json::Value::Object(trigger))
    else {
        return false;
    };
    let materialized_site = Site::trigger(&materialized_trigger, site.pointer.clone());
    let mut materialized_diagnostics = Vec::new();
    {
        let mut materialized_ctx = ShapeCtx::new(
            ctx.file,
            ctx.workflow,
            ctx.arm_scope,
            &mut materialized_diagnostics,
        );
        spec.validate(&mut materialized_ctx, &materialized_site);
        common::validate_common_fields(&mut materialized_ctx, &materialized_site, "trigger");
    }
    extend_materialized_diagnostics(ctx.diagnostics, materialized_diagnostics, source_span);
    true
}

fn materialized_trigger_field_value(
    ctx: &ShapeCtx<'_, '_, '_>,
    field: &json_spanned_value::spanned::Value,
) -> Option<(serde_json::Value, ByteSpan)> {
    if is_opaque_arm_expression(ctx.file, field) {
        return static_json_value_from_spanned_with_scope(ctx.file, field, ctx.arm_scope);
    }
    let original = to_json_value(field)?;
    let materialized =
        crate::arm::materialize_static_expressions_with_scope(original.clone(), ctx.arm_scope)?;
    (materialized != original).then_some((materialized, span(field)))
}

/// Walk an actions container (root or nested). Called recursively for every
/// `actions` / `cases[*].actions` / `default.actions` / `else.actions` /
/// `tools[*].actions` container the containing action supports.
pub(super) fn collect_action_container_shape(
    value: Option<&json_spanned_value::spanned::Value>,
    pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    arm_scope: crate::arm::ArmStaticScope<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = value else {
        return;
    };
    if arm_optional_property_absent(file, value) {
        return;
    }
    if is_opaque_arm_expression(file, value) {
        if let Some((value, source_span)) = static_json_value_from_spanned(file, value) {
            if let Some(actions) = value.as_object() {
                let ctx = JsonActionShapeContext {
                    file,
                    workflow,
                    source_span,
                    arm_scope,
                };
                collect_json_action_container_shape(actions, pointer, &ctx, diagnostics);
            } else {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-type",
                    &file.path,
                    pointer.to_owned(),
                    Some(source_span),
                    "actions must be an object",
                ));
            }
        }
        return;
    }
    let Some(actions) = as_object(value) else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer.to_owned(),
            Some(span(value)),
            "actions must be an object",
        ));
        return;
    };

    for (name, action) in actions.iter() {
        if arm_optional_property_absent(file, action) {
            continue;
        }
        let action_pointer = pointer_join(pointer, name);
        validate_operation_name_length(
            name,
            &action_pointer,
            "action",
            file,
            Some(span(action)),
            diagnostics,
        );
        if is_opaque_arm_expression(file, action) {
            // ARM can provide the whole action entry object.
            if let Some((action_value, source_span)) = static_json_value_from_spanned(file, action)
            {
                if action_value.is_object() {
                    let ctx = JsonActionShapeContext {
                        file,
                        workflow,
                        source_span,
                        arm_scope,
                    };
                    validate_json_action_shape(
                        &action_value,
                        &action_pointer,
                        pointer,
                        &ctx,
                        diagnostics,
                    );
                } else {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-invalid-type",
                        &file.path,
                        action_pointer,
                        Some(source_span),
                        "action entries must be objects",
                    ));
                }
            }
            continue;
        }
        let Some(_action_object) = as_object(action) else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &file.path,
                action_pointer,
                Some(span(action)),
                "action entries must be objects",
            ));
            continue;
        };

        let action_type_value = get(action, "type");
        let action_type =
            action_type_value.and_then(|value| static_string_from_spanned(file, value));
        if let Some(action_type) = action_type {
            let Some(spec) = registry::action_spec(&action_type) else {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-unknown-type",
                    &file.path,
                    pointer_join(&action_pointer, "type"),
                    get(action, "type").map(span),
                    format!("unknown action type '{action_type}'"),
                ));
                continue;
            };
            if !registry::known_action_type(&action_type) {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-unknown-type",
                    &file.path,
                    pointer_join(&action_pointer, "type"),
                    get(action, "type").map(span),
                    format!("unknown action type '{action_type}'"),
                ));
                continue;
            }
            {
                let site = Site::action(action, action_pointer.clone(), pointer.to_owned());
                let mut ctx = ShapeCtx::new(file, workflow, arm_scope, diagnostics);
                spec.validate(&mut ctx, &site, &action_type);
                common::validate_common_fields(&mut ctx, &site, "action");
            }
        } else if let Some(value) = action_type_value {
            if !unresolved_arm_expression_from_spanned(file, value) {
                if is_opaque_arm_expression(file, value) || as_string(value).is_none() {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-invalid-type",
                        &file.path,
                        pointer_join(&action_pointer, "type"),
                        Some(span(value)),
                        "action type must be a string",
                    ));
                } else {
                    diagnostics.push(Diagnostic::error(
                        "workflow-shape-missing-field",
                        &file.path,
                        pointer_join(&action_pointer, "type"),
                        Some(span(action)),
                        "action is missing required field 'type'",
                    ));
                }
                continue;
            } else {
                let site = Site::action(action, action_pointer.clone(), pointer.to_owned());
                let mut ctx = ShapeCtx::new(file, workflow, arm_scope, diagnostics);
                common::validate_type_independent_common_fields(&mut ctx, &site, "action");
            }
        } else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-missing-field",
                &file.path,
                pointer_join(&action_pointer, "type"),
                Some(span(action)),
                "action is missing required field 'type'",
            ));
            continue;
        }

        if let Some(run_after) = get(action, "runAfter") {
            if arm_optional_property_absent(file, run_after) {
            } else if let Some(run_after_object) = as_object(run_after) {
                validate_run_after_statuses(
                    run_after_object,
                    &pointer_join(&action_pointer, "runAfter"),
                    file,
                    arm_scope,
                    diagnostics,
                );
            } else if let Some((run_after_object, source_span)) =
                static_json_object_from_spanned(file, run_after)
            {
                validate_json_run_after_statuses(
                    &run_after_object,
                    &pointer_join(&action_pointer, "runAfter"),
                    file,
                    arm_scope,
                    source_span,
                    diagnostics,
                );
            } else if let Some(run_after_object) =
                partial_static_json_object_from_spanned(file, run_after, arm_scope)
            {
                validate_json_run_after_statuses(
                    &run_after_object,
                    &pointer_join(&action_pointer, "runAfter"),
                    file,
                    arm_scope,
                    span(run_after),
                    diagnostics,
                );
            } else if is_opaque_arm_expression(file, run_after) {
                // ARM can materialize runAfter as an object, for example with json().
            } else {
                diagnostics.push(Diagnostic::error(
                    "workflow-shape-invalid-type",
                    &file.path,
                    pointer_join(&action_pointer, "runAfter"),
                    Some(span(run_after)),
                    "runAfter must be an object",
                ));
            }
        }

        // When the child action's type is opaque we can't decide which
        // sub-containers it supports, so we permissively descend into any that
        // are present rather than raise a false "does not support" diagnostic.
        let child_action_type =
            action_type_value.and_then(|value| static_string_from_spanned(file, value));
        let child_has_opaque_type = child_action_type.is_none()
            && action_type_value
                .is_some_and(|value| unresolved_arm_expression_from_spanned(file, value));
        let child_kind =
            crate::workflow::ActionKind::from_action_type(child_action_type.as_deref());
        let mut child_ctx = SpannedActionShapeContext {
            file,
            workflow,
            arm_scope,
            diagnostics,
        };

        collect_child_action_container_shape(
            get(action, "actions"),
            &action_pointer,
            "actions",
            child_has_opaque_type || child_kind.supports_actions_container(),
            child_action_type.as_deref(),
            &mut child_ctx,
        );

        if (child_has_opaque_type || child_kind.supports_cases_container())
            && let Some(cases) = get(action, "cases").and_then(as_object)
        {
            let cases_pointer = pointer_join(&action_pointer, "cases");
            for (case_name, case_value) in cases.iter() {
                collect_action_container_shape(
                    get(case_value, "actions"),
                    &pointer_join(&pointer_join(&cases_pointer, case_name), "actions"),
                    child_ctx.file,
                    child_ctx.workflow,
                    child_ctx.arm_scope,
                    child_ctx.diagnostics,
                );
            }
        }

        for (branch, supported) in [
            ("default", child_kind.supports_default_container()),
            ("else", child_kind.supports_else_container()),
        ] {
            if (child_has_opaque_type || supported)
                && let Some(branch_value) = get(action, branch)
            {
                collect_action_container_shape(
                    get(branch_value, "actions"),
                    &pointer_join(&pointer_join(&action_pointer, branch), "actions"),
                    child_ctx.file,
                    child_ctx.workflow,
                    child_ctx.arm_scope,
                    child_ctx.diagnostics,
                );
            }
        }

        if (child_has_opaque_type || child_kind.supports_tools_container())
            && let Some(tools) = get(action, "tools").and_then(as_object)
        {
            let tools_pointer = pointer_join(&action_pointer, "tools");
            for (tool_name, tool_value) in tools.iter() {
                collect_action_container_shape(
                    get(tool_value, "actions"),
                    &pointer_join(&pointer_join(&tools_pointer, tool_name), "actions"),
                    child_ctx.file,
                    child_ctx.workflow,
                    child_ctx.arm_scope,
                    child_ctx.diagnostics,
                );
            }
        }
    }
}

fn collect_json_trigger_shape(
    triggers: &serde_json::Map<String, serde_json::Value>,
    pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    source_span: ByteSpan,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (name, trigger) in triggers {
        if materialized_arm_entry_absent(file, trigger) {
            continue;
        }
        let trigger_pointer = pointer_join(pointer, name);
        validate_operation_name_length(
            name,
            &trigger_pointer,
            "trigger",
            file,
            Some(source_span),
            diagnostics,
        );
        validate_json_trigger_shape(
            trigger,
            &trigger_pointer,
            file,
            workflow,
            source_span,
            diagnostics,
        );
    }
}

fn validate_json_trigger_shape(
    trigger: &serde_json::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    source_span: ByteSpan,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(trigger_object) = trigger.as_object() else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            trigger_pointer.to_owned(),
            Some(source_span),
            "trigger entries must be objects",
        ));
        return;
    };
    let Some(trigger_type_value) = trigger_object.get("type") else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &file.path,
            pointer_join(trigger_pointer, "type"),
            Some(source_span),
            "trigger is missing required field 'type'",
        ));
        return;
    };
    let Some(trigger_type) = trigger_type_value.as_str() else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &file.path,
            pointer_join(trigger_pointer, "type"),
            Some(source_span),
            "trigger type must be a string",
        ));
        return;
    };
    if registry::trigger_spec(trigger_type).is_none() || !registry::known_trigger_type(trigger_type)
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-unknown-type",
            &file.path,
            pointer_join(trigger_pointer, "type"),
            Some(source_span),
            format!("unknown trigger type '{trigger_type}'"),
        ));
        return;
    }
    validate_trigger_workflow_context(
        trigger_type,
        trigger_pointer,
        file,
        workflow,
        Some(source_span),
        trigger.get("recurrence").is_some(),
        diagnostics,
    );
    validate_materialized_json_trigger(
        trigger,
        trigger_pointer,
        file,
        workflow,
        source_span,
        diagnostics,
    );
}

/// Enforce Stateless-workflow trigger restrictions. `Recurrence`,
/// `SlidingWindow`, and the recurring flavors of `ApiConnection` /
/// `ApiManagement` / `Http` are not supported without persistent state.
fn validate_trigger_workflow_context(
    trigger_type: &str,
    trigger_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    source_span: Option<ByteSpan>,
    has_recurrence: bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if workflow.is_stateless()
        && (trigger_type.eq_ignore_ascii_case("Recurrence")
            || trigger_type.eq_ignore_ascii_case("SlidingWindow")
            || ((trigger_type.eq_ignore_ascii_case("ApiConnection")
                || trigger_type.eq_ignore_ascii_case("ApiManagement")
                || trigger_type.eq_ignore_ascii_case("Http"))
                && has_recurrence))
    {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &file.path,
            pointer_join(trigger_pointer, "type"),
            source_span,
            format!("{trigger_type} trigger is not supported in Stateless workflows"),
        ));
    }
}

struct SpannedActionShapeContext<'file, 'workflow, 'arm, 'diagnostics> {
    file: &'file JsonFile,
    workflow: &'file Workflow<'workflow>,
    arm_scope: crate::arm::ArmStaticScope<'arm>,
    diagnostics: &'diagnostics mut Vec<Diagnostic>,
}

fn collect_child_action_container_shape(
    value: Option<&json_spanned_value::spanned::Value>,
    parent_pointer: &str,
    field: &str,
    allowed: bool,
    action_type: Option<&str>,
    ctx: &mut SpannedActionShapeContext<'_, '_, '_, '_>,
) {
    let Some(value) = value else {
        return;
    };
    let pointer = pointer_join(parent_pointer, field);
    if !allowed {
        if arm_optional_property_absent(ctx.file, value)
            || is_opaque_arm_expression(ctx.file, value)
        {
            return;
        }
        let label = action_type.unwrap_or("action");
        ctx.diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &ctx.file.path,
            pointer,
            Some(span(value)),
            format!("{label} action does not support child actions"),
        ));
        return;
    }

    collect_action_container_shape(
        Some(value),
        &pointer,
        ctx.file,
        ctx.workflow,
        ctx.arm_scope,
        ctx.diagnostics,
    );
}

fn collect_json_action_container_shape(
    actions: &serde_json::Map<String, serde_json::Value>,
    pointer: &str,
    ctx: &JsonActionShapeContext<'_, '_, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (name, action) in actions {
        if materialized_arm_entry_absent(ctx.file, action) {
            continue;
        }
        let action_pointer = pointer_join(pointer, name);
        validate_operation_name_length(
            name,
            &action_pointer,
            "action",
            ctx.file,
            Some(ctx.source_span),
            diagnostics,
        );
        validate_json_action_shape(action, &action_pointer, pointer, ctx, diagnostics);
    }
}

struct JsonActionShapeContext<'file, 'workflow, 'arm> {
    file: &'file JsonFile,
    workflow: &'file Workflow<'workflow>,
    source_span: ByteSpan,
    arm_scope: crate::arm::ArmStaticScope<'arm>,
}

fn validate_json_action_shape(
    action: &serde_json::Value,
    action_pointer: &str,
    container_pointer: &str,
    ctx: &JsonActionShapeContext<'_, '_, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(action_object) = action.as_object() else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-type",
            &ctx.file.path,
            action_pointer.to_owned(),
            Some(ctx.source_span),
            "action entries must be objects",
        ));
        return;
    };
    let action_type_value = action_object.get("type");
    let action_type = action_type_value.and_then(static_string_from_json);
    if let Some(action_type) = action_type {
        if registry::action_spec(&action_type).is_none()
            || !registry::known_action_type(&action_type)
        {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-unknown-type",
                &ctx.file.path,
                pointer_join(action_pointer, "type"),
                Some(ctx.source_span),
                format!("unknown action type '{action_type}'"),
            ));
            return;
        }
        validate_materialized_json_action(
            action,
            action_pointer,
            container_pointer,
            ctx,
            diagnostics,
        );
    } else if let Some(value) = action_type_value {
        if !unresolved_arm_expression_from_json(ctx.file, value) {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &ctx.file.path,
                pointer_join(action_pointer, "type"),
                Some(ctx.source_span),
                "action type must be a string",
            ));
            return;
        }
    } else {
        diagnostics.push(Diagnostic::error(
            "workflow-shape-missing-field",
            &ctx.file.path,
            pointer_join(action_pointer, "type"),
            Some(ctx.source_span),
            "action is missing required field 'type'",
        ));
        return;
    }
    if let Some(run_after) = action_object.get("runAfter") {
        let run_after_pointer = pointer_join(action_pointer, "runAfter");
        if materialized_arm_entry_absent(ctx.file, run_after) {
        } else if let Some(run_after_object) = run_after.as_object() {
            validate_json_run_after_statuses(
                run_after_object,
                &run_after_pointer,
                ctx.file,
                ctx.arm_scope,
                ctx.source_span,
                diagnostics,
            );
        } else if let Some(run_after_object) =
            partial_static_json_object_from_json(run_after, ctx.arm_scope)
        {
            validate_json_run_after_statuses(
                &run_after_object,
                &run_after_pointer,
                ctx.file,
                ctx.arm_scope,
                ctx.source_span,
                diagnostics,
            );
        } else if unresolved_arm_expression_from_json(ctx.file, run_after) {
        } else {
            diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &ctx.file.path,
                run_after_pointer,
                Some(ctx.source_span),
                "runAfter must be an object",
            ));
        }
    }

    let child_action_type = action_type_value.and_then(static_string_from_json);
    let child_has_opaque_type = child_action_type.is_none()
        && action_type_value
            .is_some_and(|value| unresolved_arm_expression_from_json(ctx.file, value));
    let child_kind = crate::workflow::ActionKind::from_action_type(child_action_type.as_deref());

    collect_child_json_actions(
        action_object.get("actions"),
        action_pointer,
        "actions",
        child_has_opaque_type || child_kind.supports_actions_container(),
        child_action_type.as_deref(),
        ctx,
        diagnostics,
    );

    if (child_has_opaque_type || child_kind.supports_cases_container())
        && let Some(cases) = action_object
            .get("cases")
            .and_then(serde_json::Value::as_object)
    {
        let cases_pointer = pointer_join(action_pointer, "cases");
        for (case_name, case_value) in cases {
            collect_child_json_actions(
                case_value.get("actions"),
                &pointer_join(&cases_pointer, case_name),
                "actions",
                true,
                child_action_type.as_deref(),
                ctx,
                diagnostics,
            );
        }
    }

    for (branch, supported) in [
        ("default", child_kind.supports_default_container()),
        ("else", child_kind.supports_else_container()),
    ] {
        if (child_has_opaque_type || supported)
            && let Some(branch_value) = action_object.get(branch)
        {
            collect_child_json_actions(
                branch_value.get("actions"),
                &pointer_join(action_pointer, branch),
                "actions",
                true,
                child_action_type.as_deref(),
                ctx,
                diagnostics,
            );
        }
    }

    if (child_has_opaque_type || child_kind.supports_tools_container())
        && let Some(tools) = action_object
            .get("tools")
            .and_then(serde_json::Value::as_object)
    {
        let tools_pointer = pointer_join(action_pointer, "tools");
        for (tool_name, tool_value) in tools {
            collect_child_json_actions(
                tool_value.get("actions"),
                &pointer_join(&tools_pointer, tool_name),
                "actions",
                true,
                child_action_type.as_deref(),
                ctx,
                diagnostics,
            );
        }
    }
}

fn collect_child_json_actions(
    value: Option<&serde_json::Value>,
    parent_pointer: &str,
    field: &str,
    allowed: bool,
    action_type: Option<&str>,
    ctx: &JsonActionShapeContext<'_, '_, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = value else {
        return;
    };
    let pointer = pointer_join(parent_pointer, field);
    if !allowed {
        if materialized_arm_entry_absent(ctx.file, value)
            || unresolved_arm_expression_from_json(ctx.file, value)
        {
            return;
        }
        let label = action_type.unwrap_or("action");
        diagnostics.push(Diagnostic::error(
            "workflow-shape-invalid-context",
            &ctx.file.path,
            pointer,
            Some(ctx.source_span),
            format!("{label} action does not support child actions"),
        ));
        return;
    }
    if let Some(actions) = value.as_object() {
        collect_json_action_container_shape(actions, &pointer, ctx, diagnostics);
    }
}

/// Re-run the per-type spec on the materialized JSON view of an action.
/// Diagnostics land against a synthetic `JsonFile` and are then re-anchored to
/// the enclosing ARM span before being merged into the caller's list.
fn validate_materialized_json_action(
    action: &serde_json::Value,
    action_pointer: &str,
    container_pointer: &str,
    ctx: &JsonActionShapeContext<'_, '_, '_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(action_type) = action.get("type").and_then(serde_json::Value::as_str) else {
        return;
    };
    let Some(spec) = registry::action_spec(action_type) else {
        return;
    };
    let Some(materialized) = spanned_value_from_json(action) else {
        return;
    };
    let materialized_file = JsonFile {
        path: ctx.file.path.clone(),
        value: materialized,
    };
    let site = Site::action(
        &materialized_file.value,
        action_pointer.to_owned(),
        container_pointer.to_owned(),
    );
    let mut materialized_diagnostics = Vec::new();
    {
        let mut ctx = ShapeCtx::new(
            &materialized_file,
            ctx.workflow,
            ctx.arm_scope,
            &mut materialized_diagnostics,
        );
        spec.validate(&mut ctx, &site, action_type);
        common::validate_common_fields(&mut ctx, &site, "action");
    }
    extend_materialized_diagnostics(diagnostics, materialized_diagnostics, ctx.source_span);
}

/// Trigger counterpart to `validate_materialized_json_action`.
fn validate_materialized_json_trigger(
    trigger: &serde_json::Value,
    trigger_pointer: &str,
    file: &JsonFile,
    workflow: &Workflow<'_>,
    source_span: ByteSpan,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(trigger_type) = trigger.get("type").and_then(serde_json::Value::as_str) else {
        return;
    };
    let Some(spec) = registry::trigger_spec(trigger_type) else {
        return;
    };
    let Some(materialized) = spanned_value_from_json(trigger) else {
        return;
    };
    let materialized_file = JsonFile {
        path: file.path.clone(),
        value: materialized,
    };
    let site = Site::trigger(&materialized_file.value, trigger_pointer.to_owned());
    let mut materialized_diagnostics = Vec::new();
    {
        let mut ctx = ShapeCtx::new(
            &materialized_file,
            workflow,
            crate::arm::ArmStaticScope::default(),
            &mut materialized_diagnostics,
        );
        spec.validate(&mut ctx, &site);
        common::validate_common_fields(&mut ctx, &site, "trigger");
        triggers::validate_trigger_common_fields(
            site.value,
            &site.pointer,
            ctx.file,
            ctx.diagnostics,
        );
    }
    extend_materialized_diagnostics(diagnostics, materialized_diagnostics, source_span);
}
