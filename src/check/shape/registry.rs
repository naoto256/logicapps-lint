//! Declarative registry of action / trigger validators.
//!
//! Every supported action or trigger `type` maps to one entry in
//! `ACTION_SPECS` / `TRIGGER_SPECS`. Each entry carries a
//! [`ActionValidator`] / [`TriggerValidatorKind`] variant that pins the exact
//! function-pointer signature the validator needs — `Simple` rules take just
//! the node, `Workflow` rules need `Workflow<'_>` for kind-aware checks,
//! `Container` rules need the enclosing pointer, and `Typed` rules receive
//! the concrete `type` string so a single validator (e.g. variable updates)
//! can service several registered names.
//!
//! Keeping the fn-pointer types distinct instead of a single boxed trait
//! object is deliberate: it lets the tables stay `const`, keeps dispatch
//! inline, and prevents accidental capability creep (a `Simple` rule cannot
//! reach into the `Workflow`).
//!
//! For actions listed in [`action_validates_inputs_object`] the registry also
//! runs a materialize-then-re-validate pass: the `inputs` field is resolved
//! via ARM static evaluation and, if it materially changes, the whole action
//! is re-emitted through the same validator with the resolved value swapped
//! in, and diagnostics are rebound to the original ARM source span.

use super::materialized::{
    extend_materialized_diagnostics, spanned_value_from_json,
    static_json_value_from_spanned_with_scope,
};
use super::*;
use crate::json::to_json_value;

type SimpleActionValidator =
    fn(&json_spanned_value::spanned::Value, &str, &JsonFile, &mut Vec<Diagnostic>);
type WorkflowActionValidator =
    fn(&json_spanned_value::spanned::Value, &str, &JsonFile, &Workflow<'_>, &mut Vec<Diagnostic>);
type ContainerActionValidator =
    fn(&json_spanned_value::spanned::Value, &str, &str, &JsonFile, &mut Vec<Diagnostic>);
type TypedActionValidator = fn(
    &json_spanned_value::spanned::Value,
    &str,
    &str,
    &JsonFile,
    &Workflow<'_>,
    &mut Vec<Diagnostic>,
);
type TriggerValidator =
    fn(&json_spanned_value::spanned::Value, &str, &JsonFile, &mut Vec<Diagnostic>);
type WorkflowTriggerValidator =
    fn(&json_spanned_value::spanned::Value, &str, &JsonFile, &Workflow<'_>, &mut Vec<Diagnostic>);

/// Discriminated function-pointer set for action rules. The variants
/// partition validators by exact capability so each rule declares up-front
/// what it may read.
pub(super) enum ActionValidator {
    /// Action type is recognised but has no dedicated shape rule.
    None,
    /// Node + pointer only.
    Simple(SimpleActionValidator),
    /// Adds `Workflow<'_>` for kind-aware checks (Standard vs Consumption).
    Workflow(WorkflowActionValidator),
    /// Adds the enclosing container pointer for sibling-aware checks.
    Container(ContainerActionValidator),
    /// Receives the concrete `type` string so one validator can service
    /// multiple registered names (e.g. every variable-update flavour).
    Typed(TypedActionValidator),
}

/// One row in [`ACTION_SPECS`].
pub(super) struct ActionSpec {
    pub(super) name: &'static str,
    validator: ActionValidator,
}

impl ActionSpec {
    const fn none(name: &'static str) -> Self {
        Self {
            name,
            validator: ActionValidator::None,
        }
    }

    const fn simple(name: &'static str, validator: SimpleActionValidator) -> Self {
        Self {
            name,
            validator: ActionValidator::Simple(validator),
        }
    }

    const fn workflow(name: &'static str, validator: WorkflowActionValidator) -> Self {
        Self {
            name,
            validator: ActionValidator::Workflow(validator),
        }
    }

    const fn container(name: &'static str, validator: ContainerActionValidator) -> Self {
        Self {
            name,
            validator: ActionValidator::Container(validator),
        }
    }

    const fn typed(name: &'static str, validator: TypedActionValidator) -> Self {
        Self {
            name,
            validator: ActionValidator::Typed(validator),
        }
    }

    /// Run the validator against `site`.
    ///
    /// For action types whose `inputs` field is validated as an object, first
    /// try to statically materialize `inputs` through ARM. If materialization
    /// actually changed the value, re-run the validator on the substituted
    /// action and rebind diagnostics onto the ARM source span; otherwise fall
    /// through to the normal in-place validation.
    pub(super) fn validate(
        &self,
        ctx: &mut ShapeCtx<'_, '_, '_>,
        site: &Site<'_>,
        action_type: &str,
    ) {
        if action_validates_inputs_object(action_type)
            && self.validate_with_scoped_inputs(ctx, site, action_type)
        {
            return;
        }
        self.validate_inner(ctx, site, action_type);
    }

    fn validate_inner(&self, ctx: &mut ShapeCtx<'_, '_, '_>, site: &Site<'_>, action_type: &str) {
        match self.validator {
            ActionValidator::None => {}
            ActionValidator::Simple(validate) => {
                validate(site.value, &site.pointer, ctx.file, ctx.diagnostics)
            }
            ActionValidator::Workflow(validate) => validate(
                site.value,
                &site.pointer,
                ctx.file,
                ctx.workflow,
                ctx.diagnostics,
            ),
            ActionValidator::Container(validate) => validate(
                site.value,
                &site.pointer,
                site.container_pointer(),
                ctx.file,
                ctx.diagnostics,
            ),
            ActionValidator::Typed(validate) => validate(
                site.value,
                &site.pointer,
                action_type,
                ctx.file,
                ctx.workflow,
                ctx.diagnostics,
            ),
        }
    }
}

/// One row in [`TRIGGER_SPECS`]. `optional_recurrence` piggybacks the
/// recurrence sub-validator onto trigger types that permit but do not
/// require a `recurrence` block (e.g. `ApiManagement`).
pub(super) struct TriggerSpec {
    pub(super) name: &'static str,
    validator: TriggerValidatorKind,
    optional_recurrence: bool,
}

/// Trigger analogue of [`ActionValidator`]. Triggers have no container and
/// no per-type shared validators, so the `Container` and `Typed` variants
/// are absent.
enum TriggerValidatorKind {
    None,
    Simple(TriggerValidator),
    Workflow(WorkflowTriggerValidator),
}

impl TriggerSpec {
    const fn none(name: &'static str) -> Self {
        Self {
            name,
            validator: TriggerValidatorKind::None,
            optional_recurrence: false,
        }
    }

    const fn new(name: &'static str, validator: TriggerValidator) -> Self {
        Self {
            name,
            validator: TriggerValidatorKind::Simple(validator),
            optional_recurrence: false,
        }
    }

    const fn with_optional_recurrence(name: &'static str, validator: TriggerValidator) -> Self {
        Self {
            name,
            validator: TriggerValidatorKind::Simple(validator),
            optional_recurrence: true,
        }
    }

    const fn workflow(name: &'static str, validator: WorkflowTriggerValidator) -> Self {
        Self {
            name,
            validator: TriggerValidatorKind::Workflow(validator),
            optional_recurrence: false,
        }
    }

    /// Run the trigger validator against `site` and, if applicable, the
    /// shared optional-recurrence check.
    pub(super) fn validate(&self, ctx: &mut ShapeCtx<'_, '_, '_>, site: &Site<'_>) {
        match self.validator {
            TriggerValidatorKind::None => {}
            TriggerValidatorKind::Simple(validate) => {
                validate(site.value, &site.pointer, ctx.file, ctx.diagnostics);
            }
            TriggerValidatorKind::Workflow(validate) => validate(
                site.value,
                &site.pointer,
                ctx.file,
                ctx.workflow,
                ctx.diagnostics,
            ),
        }
        if self.optional_recurrence {
            triggers::validate_optional_recurrence(
                site.value,
                &site.pointer,
                ctx.file,
                ctx.diagnostics,
            );
        }
    }
}

/// Actions whose validators require `inputs` to be a concrete object. Only
/// these types trigger the ARM-materialize-then-re-validate pass; other
/// actions either do not touch `inputs` or accept opaque expressions there
/// without further inspection.
fn action_validates_inputs_object(action_type: &str) -> bool {
    matches!(
        action_type,
        "ApiConnection"
            | "ApiConnectionWebhook"
            | "ApiManagement"
            | "Function"
            | "Http"
            | "HttpWebhook"
            | "Join"
            | "Response"
            | "SendToBatch"
            | "AppendToArrayVariable"
            | "AppendToStringVariable"
            | "DecrementVariable"
            | "InitializeVariable"
            | "IncrementVariable"
            | "SetVariable"
            | "Workflow"
    )
}

impl ActionSpec {
    // Attempt an ARM-materialized re-run of the validator with `inputs`
    // resolved. Returns `true` when the caller must skip in-place validation
    // — either because materialization already produced diagnostics or
    // because the resolved shape is not an object (which is itself a
    // reportable error). Returns `false` when nothing materialized and the
    // caller should validate the site as authored.
    fn validate_with_scoped_inputs(
        &self,
        ctx: &mut ShapeCtx<'_, '_, '_>,
        site: &Site<'_>,
        action_type: &str,
    ) -> bool {
        let Some(inputs) = get(site.value, "inputs") else {
            return false;
        };
        let Some((value, source_span)) = materialized_inputs_value(ctx, inputs) else {
            return false;
        };
        if !value.is_object() {
            ctx.diagnostics.push(Diagnostic::error(
                "workflow-shape-invalid-type",
                &ctx.file.path,
                pointer_join(&site.pointer, "inputs"),
                Some(source_span),
                "action field 'inputs' must be an object",
            ));
            return true;
        }

        let Some(mut action) = to_json_value(site.value).and_then(|value| match value {
            serde_json::Value::Object(object) => Some(object),
            _ => None,
        }) else {
            return false;
        };
        action.insert("inputs".to_owned(), value);
        let Some(materialized_action) = spanned_value_from_json(&serde_json::Value::Object(action))
        else {
            return false;
        };
        let materialized_site = Site::action(
            &materialized_action,
            site.pointer.clone(),
            site.container_pointer().to_owned(),
        );
        let mut materialized_diagnostics = Vec::new();
        {
            let mut materialized_ctx = ShapeCtx::new(
                ctx.file,
                ctx.workflow,
                ctx.arm_scope,
                &mut materialized_diagnostics,
            );
            self.validate_inner(&mut materialized_ctx, &materialized_site, action_type);
        }
        extend_materialized_diagnostics(ctx.diagnostics, materialized_diagnostics, source_span);
        true
    }
}

fn materialized_inputs_value(
    ctx: &ShapeCtx<'_, '_, '_>,
    inputs: &json_spanned_value::spanned::Value,
) -> Option<(serde_json::Value, crate::diagnostic::ByteSpan)> {
    if is_opaque_arm_expression(ctx.file, inputs) {
        return static_json_value_from_spanned_with_scope(ctx.file, inputs, ctx.arm_scope);
    }
    let original = to_json_value(inputs)?;
    let materialized =
        crate::arm::materialize_static_expressions_with_scope(original.clone(), ctx.arm_scope)?;
    (materialized != original).then_some((materialized, span(inputs)))
}

/// Declarative table of every supported action `type`. Order does not
/// matter — lookup is case-insensitive linear scan via [`action_spec`].
pub(super) const ACTION_SPECS: &[ActionSpec] = &[
    ActionSpec::workflow(
        "ApiConnection",
        actions::connectors::validate_api_connection_action,
    ),
    ActionSpec::workflow(
        "ApiConnectionWebhook",
        actions::connectors::validate_api_connection_webhook_action,
    ),
    ActionSpec::workflow(
        "ApiManagement",
        actions::connectors::validate_api_management_action,
    ),
    ActionSpec::simple("Batch", actions::integration::validate_batch_action),
    ActionSpec::simple(
        "SendToBatch",
        actions::integration::validate_send_to_batch_action,
    ),
    ActionSpec::simple("Compose", actions::data::validate_compose_action),
    ActionSpec::simple("Expression", actions::data::validate_expression_action),
    ActionSpec::simple(
        "FlatFileDecoding",
        actions::integration::validate_flat_file_action,
    ),
    ActionSpec::simple(
        "FlatFileEncoding",
        actions::integration::validate_flat_file_action,
    ),
    ActionSpec::workflow("Function", actions::connectors::validate_function_action),
    ActionSpec::workflow("Http", actions::connectors::validate_http_action),
    ActionSpec::workflow(
        "HttpWebhook",
        actions::connectors::validate_http_webhook_action,
    ),
    ActionSpec::simple(
        "IntegrationAccountArtifactLookup",
        actions::integration::validate_integration_account_artifact_lookup_action,
    ),
    ActionSpec::workflow(
        "JavaScriptCode",
        actions::data::validate_javascript_code_action,
    ),
    ActionSpec::simple("Join", actions::data::validate_join_action),
    ActionSpec::simple("Liquid", actions::integration::validate_liquid_action),
    ActionSpec::simple("ParseJson", actions::data::validate_parse_json_action),
    ActionSpec::workflow(
        "PowershellCode",
        actions::data::validate_powershell_code_action,
    ),
    ActionSpec::simple("Query", actions::data::validate_query_action),
    ActionSpec::workflow("Response", actions::control::validate_response_action),
    ActionSpec::none("ServiceProvider"),
    ActionSpec::simple("Foreach", actions::control::validate_foreach_action),
    ActionSpec::simple("If", actions::control::validate_if_action),
    ActionSpec::simple("Scope", actions::control::validate_scope_action),
    ActionSpec::simple("Switch", actions::control::validate_switch_action),
    ActionSpec::workflow(
        "Until",
        actions::control::validate_until_action_with_workflow,
    ),
    ActionSpec::simple("Select", actions::data::validate_select_action),
    ActionSpec::simple("Table", actions::data::validate_table_action),
    ActionSpec::workflow("Terminate", actions::control::validate_terminate_action),
    ActionSpec::typed(
        "AppendToArrayVariable",
        actions::variables::validate_variable_update_action,
    ),
    ActionSpec::typed(
        "AppendToStringVariable",
        actions::variables::validate_variable_update_action,
    ),
    ActionSpec::workflow("Agent", actions::agent::validate_agent_action),
    ActionSpec::typed(
        "DecrementVariable",
        actions::variables::validate_variable_update_action,
    ),
    ActionSpec::typed(
        "IncrementVariable",
        actions::variables::validate_variable_update_action,
    ),
    ActionSpec::container(
        "InitializeVariable",
        actions::variables::validate_initialize_variable_action,
    ),
    ActionSpec::typed(
        "SetVariable",
        actions::variables::validate_variable_update_action,
    ),
    ActionSpec::simple("Wait", actions::control::validate_wait_action),
    ActionSpec::workflow("Workflow", actions::integration::validate_workflow_action),
    ActionSpec::simple(
        "XmlValidation",
        actions::integration::validate_xml_validation_action,
    ),
    ActionSpec::simple("Xslt", actions::integration::validate_xslt_action),
];

/// Declarative table of every supported trigger `type`.
pub(super) const TRIGGER_SPECS: &[TriggerSpec] = &[
    TriggerSpec::workflow("ApiConnection", triggers::validate_api_connection_trigger),
    TriggerSpec::workflow(
        "ApiConnectionWebhook",
        triggers::validate_api_connection_trigger,
    ),
    TriggerSpec::with_optional_recurrence(
        "ApiManagement",
        triggers::validate_api_management_trigger,
    ),
    TriggerSpec::workflow("Batch", triggers::validate_batch_trigger),
    TriggerSpec::new("Http", triggers::validate_http_trigger),
    TriggerSpec::workflow("HttpWebhook", triggers::validate_http_webhook_trigger),
    TriggerSpec::new("Recurrence", triggers::validate_recurrence_trigger),
    TriggerSpec::new("Request", triggers::validate_request_trigger),
    TriggerSpec::none("ServiceProvider"),
    TriggerSpec::new("SlidingWindow", triggers::validate_sliding_window_trigger),
];

/// Look up the spec for `action_type`, case-insensitive.
pub(super) fn action_spec(action_type: &str) -> Option<&'static ActionSpec> {
    ACTION_SPECS
        .iter()
        .find(|spec| spec.name.eq_ignore_ascii_case(action_type))
}

/// Look up the spec for `trigger_type`, case-insensitive.
pub(super) fn trigger_spec(trigger_type: &str) -> Option<&'static TriggerSpec> {
    TRIGGER_SPECS
        .iter()
        .find(|spec| spec.name.eq_ignore_ascii_case(trigger_type))
}

/// Whether `action_type` is registered. Used by the unknown-type rule so
/// its answer stays consistent with the registry.
pub(super) fn known_action_type(action_type: &str) -> bool {
    ACTION_SPECS
        .iter()
        .any(|spec| spec.name.eq_ignore_ascii_case(action_type))
}

/// Whether `trigger_type` is registered.
pub(super) fn known_trigger_type(trigger_type: &str) -> bool {
    TRIGGER_SPECS
        .iter()
        .any(|spec| spec.name.eq_ignore_ascii_case(trigger_type))
}
