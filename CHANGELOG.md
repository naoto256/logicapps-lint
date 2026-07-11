# Changelog

## 0.1.0 - 2026-07-11

Initial public release.

### Added

- CLI linter for Azure Logic Apps workflow JSON files, Standard project
  directories, template packages, and ARM deployment templates passed directly.
- Shallow WDL expression scanner covering reference helpers (`outputs`, `body`,
  `variables`, `parameters`, `items`, `result`, `iterationIndexes`, `action`,
  `listCallbackUrl`, `formData*`, `multipartBody`), arity checks, escape and
  interpolation syntax, and root-expression plain-text suffix detection.
- Workflow graph summary that flattens nested containers (`Foreach`, `If`,
  `Scope`, `Switch`, `Until`, `Agent`) and tracks per-node opaque-ARM markers.
- Reference resolution against the workflow graph: unknown actions, missing
  `runAfter` paths, uninitialised variables, out-of-scope `item()` / `items()`,
  unknown scoped actions, trigger-vs-action ordering, tracked-properties context
  restrictions, and duplicate action names.
- Shape checks for per-action / per-trigger required fields, HTTP URI and method
  shape, retry policies, recurrence and schedule fields, ISO 8601 duration and
  date-time formats, static-result declarations, secure-data settings, runtime
  concurrency limits, and operation-options tokens. Integer-typed fields such
  as `Wait.interval.count` and `Recurrence.count` accept WDL expressions
  (`@parameters(...)`) alongside literal integers, matching runtime evaluation.
- Project checks for Standard `parameters.json` / `workflowparameters.json`,
  `connections.json`, and Logic Apps template package manifests, plus embedded
  ARM template workflows with static parameter and variable evaluation.
- Stable JSON diagnostic contract (`--format json`) suitable for CI, and a
  human-readable renderer with source snippets and JSON Pointer anchors.
- CLI overrides `--warn <CODE>` and `--allow <CODE>` (both repeatable) to
  downgrade or suppress specific diagnostic codes without patching source.
- `--strict` opt-in that reports the documented schema literally. By default
  the linter accepts case variants that the Logic Apps runtime tolerates
  (uppercase `runAfter` statuses such as `SUCCEEDED`, lowercase parameter
  types such as `string`) and downgrades registry-gap diagnostics
  (`workflow-shape-unknown-type`, unregistered `kind` / `operationOptions`
  tokens) to warnings so the run does not fail on Logic Apps features that
  post-date this release. `--strict` restores literal enforcement.
- Library entry points `lint_path` and `relax_diagnostics` for embedding
  the linter and applying the strict / lenient policy from other tooling.
