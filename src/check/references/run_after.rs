//! Index over the workflow's runAfter graph.
//!
//! Built once per workflow and reused to answer:
//!   * "does this runAfter edge point at a visible sibling?"
//!   * "does this runAfter graph contain a cycle?"
//!   * "can action A be reached from site S via runAfter chains, walking up
//!     through parent scopes when necessary?"
//!
//! Sibling scope matters: runAfter edges are resolved inside a single
//! `container_pointer` (the `actions` object that owns them), not across the
//! entire workflow. Cross-scope reachability requires climbing to a parent
//! action and continuing the search there — hence the parent map.

use crate::workflow::{RunAfterRef, Workflow};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct RunAfterIndex {
    /// (container, action) -> names of direct runAfter dependencies.
    dependencies: BTreeMap<(String, String), Vec<String>>,
    /// Set of (container, action) tuples that actually exist. Used to detect
    /// runAfter targets naming a non-existent sibling.
    visible_actions: BTreeSet<(String, String)>,
    /// (container, action) -> action names whose outputs are reachable from
    /// inside that action's subtree, i.e. the action itself plus every
    /// descendant action. Lets nested sites cite ancestor-scope actions once
    /// the parent action has been reached via runAfter.
    covered_references: BTreeMap<(String, String), BTreeSet<String>>,
    actions_by_pointer: BTreeMap<String, crate::workflow::ActionInfo>,
    /// Child action pointer -> parent action pointer. Absent when the action
    /// lives at the top-level `actions` object.
    parent_by_pointer: BTreeMap<String, String>,
    /// Memoized reachability results; the graph is a DAG once cycles are
    /// stripped, but the same query recurs across many sites.
    reachability_cache: BTreeMap<(String, String, String), bool>,
}

impl RunAfterIndex {
    pub(super) fn new(workflow: &Workflow<'_>) -> Self {
        let mut dependencies = BTreeMap::new();
        let mut visible_actions = BTreeSet::new();
        let mut covered_references = BTreeMap::new();
        let mut actions_by_pointer = BTreeMap::new();

        for action in &workflow.action_list {
            actions_by_pointer.insert(action.pointer.clone(), action.clone());
        }
        let mut parent_by_pointer = BTreeMap::new();
        for action in &workflow.action_list {
            // The container of a nested action lives inside another action
            // (e.g. `/actions/Outer/actions`); walking outward until we find
            // an action pointer identifies the parent.
            if let Some(parent) =
                Self::action_containing_pointer(&actions_by_pointer, &action.container_pointer)
            {
                parent_by_pointer.insert(action.pointer.clone(), parent.pointer.clone());
            }
        }

        for action in &workflow.action_list {
            visible_actions.insert((action.container_pointer.clone(), action.name.clone()));
            dependencies.insert(
                (action.container_pointer.clone(), action.name.clone()),
                action_run_after_dependencies(action),
            );
            // Seed each action's coverage with its own name; descendants are
            // folded in below.
            covered_references.insert(
                (action.container_pointer.clone(), action.name.clone()),
                BTreeSet::from([action.name.clone()]),
            );
        }

        for action in &workflow.action_list {
            // Propagate this action's name up through every ancestor scope so
            // ancestors advertise the transitive set of descendants they cover.
            // This lets `reaches_action` conclude that reaching `Outer` also
            // reaches `Outer/Inner` outputs from sites outside `Outer`.
            let mut child_pointer = action.pointer.as_str();
            while let Some(parent_pointer) = parent_by_pointer.get(child_pointer)
                && let Some(parent) = actions_by_pointer.get(parent_pointer)
            {
                if let Some(covered) = covered_references
                    .get_mut(&(parent.container_pointer.clone(), parent.name.clone()))
                {
                    covered.insert(action.name.clone());
                }
                child_pointer = parent_pointer;
            }
        }

        Self {
            dependencies,
            visible_actions,
            covered_references,
            actions_by_pointer,
            parent_by_pointer,
            reachability_cache: BTreeMap::new(),
        }
    }

    /// Longest-prefix lookup: walk parent segments of `pointer` until we hit
    /// a pointer that names an action. Returns None if no ancestor is an
    /// action (i.e. the pointer lives at workflow scope).
    fn action_containing_pointer<'a>(
        actions_by_pointer: &'a BTreeMap<String, crate::workflow::ActionInfo>,
        pointer: &str,
    ) -> Option<&'a crate::workflow::ActionInfo> {
        let mut candidate = pointer;
        loop {
            if let Some(action) = actions_by_pointer.get(candidate) {
                return Some(action);
            }
            let (parent, _last) = candidate.rsplit_once('/')?;
            candidate = parent;
        }
    }

    /// Innermost action that owns a given JSON site.
    pub(super) fn containing_action(
        &self,
        site_pointer: &str,
    ) -> Option<crate::workflow::ActionInfo> {
        Self::action_containing_pointer(&self.actions_by_pointer, site_pointer).cloned()
    }

    /// Enclosing action of `action`, or None if it is at top level.
    pub(super) fn parent_action(
        &self,
        action: &crate::workflow::ActionInfo,
    ) -> Option<crate::workflow::ActionInfo> {
        self.parent_by_pointer
            .get(&action.pointer)
            .and_then(|parent_pointer| self.actions_by_pointer.get(parent_pointer))
            .cloned()
    }

    /// True when the reference names the same action that hosts the site.
    /// Self-references are only ever accepted under trackedProperties; the
    /// caller checks the trackedProperties context separately.
    pub(super) fn site_references_self_action(
        &self,
        site_pointer: &str,
        reference_name: &str,
    ) -> bool {
        self.containing_action(site_pointer)
            .is_some_and(|action| action.name == reference_name)
    }

    /// True when the site lives at (or under) the containing action's
    /// `trackedProperties` field — the only place a self-action reference is
    /// legal.
    pub(super) fn action_tracked_properties_allowed_at(&self, site_pointer: &str) -> bool {
        let Some(action) = self.containing_action(site_pointer) else {
            return false;
        };
        site_pointer
            .strip_prefix(&action.pointer)
            .is_some_and(|rest| {
                rest == "/trackedProperties" || rest.starts_with("/trackedProperties/")
            })
    }

    pub(super) fn dependency_is_visible(&self, reference: &RunAfterRef) -> bool {
        // `runAfter` dependencies are sibling edges inside the same action container,
        // not global action-name lookups.
        self.visible_actions.contains(&(
            reference.container_pointer.clone(),
            reference.dependency.clone(),
        ))
    }

    /// Whether the runAfter edge closes a cycle within its container. We DFS
    /// from the dependency; hitting the origin action means the graph loops.
    pub(super) fn creates_cycle(&self, reference: &RunAfterRef) -> bool {
        let mut pending = vec![reference.dependency.clone()];
        let mut seen = BTreeSet::new();

        while let Some(action_name) = pending.pop() {
            if action_name == reference.action {
                return true;
            }
            // `seen` doubles as the visited set for the DFS and guards against
            // pre-existing cycles unrelated to this edge.
            if !seen.insert(action_name.clone()) {
                continue;
            }
            pending.extend(self.dependencies_for(&reference.container_pointer, &action_name));
        }

        false
    }

    fn dependencies_for(&self, container_pointer: &str, action_name: &str) -> Vec<String> {
        self.dependencies
            .get(&(container_pointer.to_owned(), action_name.to_owned()))
            .cloned()
            .unwrap_or_default()
    }

    /// True if `action` has a runAfter edge we cannot reason about — either
    /// an opaque ARM-authored value, or a dependency naming a missing sibling.
    /// Downstream reachability checks treat such actions as permissive to
    /// avoid piling secondary diagnostics onto a graph we already know is
    /// incomplete.
    pub(super) fn has_unresolved_run_after(&self, action: &crate::workflow::ActionInfo) -> bool {
        if action.has_opaque_run_after {
            return true;
        }
        self.dependencies_for(&action.container_pointer, &action.name)
            .into_iter()
            .any(|dependency| {
                !self
                    .visible_actions
                    .contains(&(action.container_pointer.clone(), dependency))
            })
    }

    /// True if `reference_name` is covered by `action`'s subtree (`action`
    /// itself or one of its descendants).
    pub(super) fn action_covers_reference(
        &self,
        action: &crate::workflow::ActionInfo,
        reference_name: &str,
    ) -> bool {
        self.covered_references
            .get(&(action.container_pointer.clone(), action.name.clone()))
            .is_some_and(|covered| covered.contains(reference_name))
    }

    /// Reachability query: starting from `action_name`, can we reach an
    /// action whose subtree covers `reference_name` by following runAfter
    /// edges within `container_pointer`?
    pub(super) fn reaches_action(
        &mut self,
        container_pointer: &str,
        action_name: &str,
        reference_name: &str,
    ) -> bool {
        self.dependency_covers_reference(
            container_pointer,
            action_name,
            reference_name,
            &mut BTreeSet::new(),
        )
    }

    fn dependency_covers_reference(
        &mut self,
        container_pointer: &str,
        action_name: &str,
        reference_name: &str,
        visiting: &mut BTreeSet<(String, String, String)>,
    ) -> bool {
        let key = (
            container_pointer.to_owned(),
            action_name.to_owned(),
            reference_name.to_owned(),
        );
        if let Some(cached) = self.reachability_cache.get(&key) {
            return *cached;
        }
        if !visiting.insert(key.clone()) {
            return false;
        }

        let mut reachable = false;
        for dependency in self.dependencies_for(container_pointer, action_name) {
            // A dependency whose own runAfter is opaque might reach anything;
            // treat it as reachable rather than emit a cascade of false
            // positives from an unknown graph shape.
            if self.actions_by_pointer.values().any(|action| {
                action.container_pointer == container_pointer
                    && action.name == dependency
                    && action.has_opaque_run_after
            }) {
                reachable = true;
                break;
            }
            if self
                .covered_references
                .get(&(container_pointer.to_owned(), dependency.clone()))
                .is_some_and(|covered| covered.contains(reference_name))
            {
                reachable = true;
                break;
            }
            if self.dependency_covers_reference(
                container_pointer,
                &dependency,
                reference_name,
                visiting,
            ) {
                reachable = true;
                break;
            }
        }
        visiting.remove(&key);
        self.reachability_cache.insert(key, reachable);
        reachable
    }
}

fn action_run_after_dependencies(action: &crate::workflow::ActionInfo) -> Vec<String> {
    action
        .run_after
        .iter()
        .map(|dependency| dependency.dependency.clone())
        .collect()
}
