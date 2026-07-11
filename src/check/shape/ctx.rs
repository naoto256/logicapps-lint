//! Bundle types passed through the shape rules.
//!
//! `ShapeCtx` groups the immutable inputs (`file`, `workflow`, `arm_scope`)
//! with the mutable diagnostic sink so rules can be written as methods on a
//! single receiver instead of six-parameter free functions. `Site` names a
//! validation target — either a trigger (no container) or an action (whose
//! `container_pointer` is the JSON pointer of the enclosing `actions` object,
//! needed for cross-sibling checks like `runAfter`).
//!
//! Both types are adopted incrementally: many older rules still take the
//! individual references directly. New code is expected to thread `ShapeCtx`
//! / `Site` end to end; the shims live on `registry.rs`.

use super::*;

/// Immutable rule inputs bundled with the mutable diagnostic sink.
pub(super) struct ShapeCtx<'a, 'w, 'arm> {
    pub(super) file: &'a JsonFile,
    pub(super) workflow: &'a Workflow<'w>,
    pub(super) arm_scope: crate::arm::ArmStaticScope<'arm>,
    pub(super) diagnostics: &'a mut Vec<Diagnostic>,
}

impl<'a, 'w, 'arm> ShapeCtx<'a, 'w, 'arm> {
    pub(super) fn new(
        file: &'a JsonFile,
        workflow: &'a Workflow<'w>,
        arm_scope: crate::arm::ArmStaticScope<'arm>,
        diagnostics: &'a mut Vec<Diagnostic>,
    ) -> Self {
        Self {
            file,
            workflow,
            arm_scope,
            diagnostics,
        }
    }
}

/// A single validation target: the node value plus its JSON pointer, and — for
/// actions — the pointer of the enclosing `actions` object so sibling-aware
/// checks (runAfter, container membership) can address peers.
pub(super) struct Site<'a> {
    pub(super) value: &'a json_spanned_value::spanned::Value,
    pub(super) pointer: String,
    pub(super) container_pointer: Option<String>,
}

impl<'a> Site<'a> {
    /// Trigger sites have no container — triggers live at the workflow root.
    pub(super) fn trigger(value: &'a json_spanned_value::spanned::Value, pointer: String) -> Self {
        Self {
            value,
            pointer,
            container_pointer: None,
        }
    }

    /// Action sites carry the enclosing `actions` object pointer so
    /// container-scoped rules (runAfter targets, scope membership) can resolve
    /// sibling nodes without re-walking the tree.
    pub(super) fn action(
        value: &'a json_spanned_value::spanned::Value,
        pointer: String,
        container_pointer: String,
    ) -> Self {
        Self {
            value,
            pointer,
            container_pointer: Some(container_pointer),
        }
    }

    /// Container pointer accessor. Panics if called on a trigger site — the
    /// caller is expected to know which flavour of `Site` it holds.
    pub(super) fn container_pointer(&self) -> &str {
        self.container_pointer
            .as_deref()
            .expect("action site has a container pointer")
    }
}
