use super::*;

// Placeholder for the Agent action shape validator.
//
// The Agent action was introduced by Microsoft as a Logic Apps host for
// LLM-driven tool orchestration. Its input schema (model configuration,
// tool set, chat history, system messages) is still evolving and there is
// no stable public contract yet. This module reserves the validator slot
// in the registry so that when the schema stabilizes the change is a
// single-file addition rather than a new dispatch path.
//
// The `&mut Vec<Diagnostic>` signature matches the shared validator shape
// used by every other action registered with `ActionSpec::workflow`; the
// clippy `ptr_arg` lint is silenced because narrowing this signature would
// diverge from the sibling validators.
#[allow(clippy::ptr_arg)]
pub(in crate::check::shape) fn validate_agent_action(
    _action: &json_spanned_value::spanned::Value,
    _action_pointer: &str,
    _file: &JsonFile,
    _workflow: &Workflow<'_>,
    _diagnostics: &mut Vec<Diagnostic>,
) {
}
