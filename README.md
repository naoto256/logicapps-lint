# logicapps-lint

[![CI](https://github.com/naoto256/logicapps-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/naoto256/logicapps-lint/actions/workflows/ci.yml)
[![Release](https://github.com/naoto256/logicapps-lint/actions/workflows/release.yml/badge.svg)](https://github.com/naoto256/logicapps-lint/actions/workflows/release.yml)
[![GitHub release](https://img.shields.io/github/v/release/naoto256/logicapps-lint?sort=semver&display_name=tag)](https://github.com/naoto256/logicapps-lint/releases/latest)
[![Dependencies](https://deps.rs/repo/github/naoto256/logicapps-lint/status.svg)](https://deps.rs/repo/github/naoto256/logicapps-lint)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`logicapps-lint` is a local linter for Azure Logic Apps workflow definitions.

It is an unofficial tool. It is not affiliated with, endorsed by, or supported by
Microsoft.

## Why

Logic Apps Standard workflows can fail late: after deployment, in the portal, or
at runtime. This tool catches local, statically visible issues before that loop.

## Current Checks

- Malformed workflow JSON and malformed project JSON files used by the workflow
- Inputs that do not contain any discovered workflow definitions
- Invalid workflow shape for fields the linter depends on
- Unknown action and trigger types, plus selected public-schema shallow shape checks. The action
  allowlist includes selected Logic Apps Standard action types that are not present in the
  public 2016 workflow definition schema.
- Missing required fields for `Foreach`, `Until`, `Scope`, `If`, `Switch`, and trigger entries
- Invalid expression field types for `Foreach`, `Until`, `If`, and `Switch`
- Invalid `Recurrence.frequency` and `Request.kind` enum values
- Missing required input fields for selected built-in actions such as `Http`, `ApiConnection`, `Response`, and `Join`
- Invalid `Until.limit` shape for the statically visible `count` and `timeout` fields
- Invalid `runAfter` shape, unsupported statuses, unknown references, trigger references, and cycles
- Invalid HTTP URI shape and method allowlist for `Http`, `ApiConnection*`, `ApiManagement`, `Function`, and webhook trigger inputs
- Invalid retry-policy shape and ISO 8601 duration bounds, `Recurrence.schedule` shape, and `SlidingWindow` window semantics
- Invalid ISO 8601 duration or date-time formats and case-sensitive Windows time-zone enum values
- Invalid `staticResults` declarations cross-checked against the action or trigger type
- Invalid `secureData` / secure input/output settings for actions and triggers that support them
- Invalid runtime concurrency limits (`runs`, `maximumWaitingRuns`, `repetitions`) with Standard versus Consumption bounds
- Invalid `operationOptions` tokens against the runtime allowlist
- Unclosed WDL interpolation, unclosed or mismatched delimiters, invalid arity or missing first arguments for reference functions, double-quoted literals, and plain-text suffixes after root expressions
- Duplicate action names across workflow scopes
- Unknown WDL action references from `actions()`, `outputs()`, `body()`,
  `formDataValue()`, `formDataMultiValues()`, and `multipartBody()`
- Zero-argument `action()` and `listCallbackUrl()` used outside their allowed contexts (`trackedProperties`, webhook unsubscribe, `Until` expressions, or webhook actions and triggers)
- `trackedProperties` expressions that reference anything other than the current action or trigger and workflow parameters
- `variables()` referenced before its `InitializeVariable` action is reachable via `runAfter`, and `SetVariable` self-references
- Action output references that are not reachable through a `runAfter` dependency path
- Unknown scoped action references from `result()` and `result()` references that are not reachable through a `runAfter` dependency path
- Unknown `variables()` references when no `InitializeVariable` action defines the variable
- Unknown `parameters()` references when the name is absent from the workflow definition and project parameter sources
- Unknown `items()` references when the target is not an in-scope `Foreach` action, and out-of-scope `item()`
- Unknown `iterationIndexes()` references when the target is not an in-scope `Until` action
- Missing project parameter values for declared workflow parameters
- Invalid project parameter entries in Standard `parameters.json` / `workflowparameters.json`
- Invalid expression functions in Standard `parameters.json`, `workflowparameters.json`, and `connections.json`
- Missing `connections.json` `@parameters()` values and malformed WDL expressions in `connections.json`
- Missing project connection entries for managed API, service-provider, and function connection references
- Logic Apps template package `manifest.json` parameters and connections
- Embedded workflow definitions in ARM template JSON files when the file is passed directly

## Non-goals

- Full Azure runtime equivalence
- Connector schema validation
- WDL type inference
- Deployment validation
- Automatic discovery of every ARM template file in a directory tree

## Install

### Homebrew (macOS, Linux)

```sh
brew install naoto256/logicapps-lint/logicapps-lint
```

### Direct download

Every release publishes archives for macOS (arm64/x86_64), Linux
(arm64/x86_64), and Windows (x86_64) at
<https://github.com/naoto256/logicapps-lint/releases>. Download the archive
that matches your platform, extract `logicapps-lint` (or `logicapps-lint.exe`),
and put it somewhere on your `PATH`. Each archive ships alongside a `sha256`
checksum file so integrity can be verified before installing.

### From source

Requires Rust 1.88 or later (edition 2024).

From a local checkout:

```sh
cargo install --path .
```

After the crate is published:

```sh
cargo install logicapps-lint
```

## Usage

```sh
logicapps-lint path/to/logic-app-standard-project
logicapps-lint path/to/workflow.json
logicapps-lint path/to/azuredeploy.json
logicapps-lint path/to/project --format json
logicapps-lint                                  # equivalent to `logicapps-lint .`
```

The path argument is optional. When omitted, it defaults to `.` — the current
working directory is linted as if it had been passed explicitly.

### Diagnostic Overrides

- `--warn <CODE>` (repeatable): downgrade the given diagnostic code to warning
  severity. A run that emits only warnings exits `0`.
- `--allow <CODE>` (repeatable): suppress the given diagnostic code entirely.
- `--strict`: enforce the documented schema literally. By default the linter
  accepts case variants the Logic Apps runtime tolerates (uppercase `runAfter`
  statuses such as `SUCCEEDED`, lowercase parameter types such as `string`)
  and downgrades registry-gap diagnostics (`workflow-shape-unknown-type`,
  unregistered `kind` / `operationOptions` tokens) to warnings so the run
  does not fail on Logic Apps features that post-date this release.
  `--strict` restores literal enforcement — pass it when your policy is
  "match the published schema exactly, regardless of runtime tolerance."

`--allow` takes precedence over `--warn` when both name the same code.
`--strict` is applied before `--allow` / `--warn`, so a suppressed or
downgraded code stays that way in either strictness mode.

When given a directory, `logicapps-lint` recursively finds `workflow.json`
files under that root. During recursive traversal, common version-control and
build-output directories (`.git`, `target`, and a small set of generated-artifact
directory names) are excluded; an explicitly supplied input root with one of
those names is still linted.
For Standard `workflow.json` files, `parameters.json`,
`workflowparameters.json`, `connections.json`, and Logic Apps template
`manifest.json` files are read from the nearest project ancestors when present.
For Standard projects, `host.json` is treated as the project boundary.
If both parameter file names exist in the nearest parameter directory, their
parameter names are merged. For template manifests, the nearest `manifest.json`
is the package boundary.

When an ARM template JSON file is passed directly, embedded workflow definitions
are linted in place. ARM template `parameters` and `variables` sections are
statically evaluated where possible so workflow diagnostics can point at the
authored expression bytes rather than at a value that only exists after
deployment. Expressions that require deployment-time context (for example
`resourceGroup()` or `reference()`) are treated as opaque and skipped rather
than misreported. Sibling ARM deployment parameter files are not treated as
Logic Apps Standard project parameter files.

## Human Output

The default human format shows the rule code, source location, highlighted JSON,
and stable JSON Pointer:

```text
error[workflow-shape-unknown-type]: unknown action type 'InvokeWorkflow'
  --> Workflow/workflow.json:55:33
   |
55 |                         "type": "InvokeWorkflow",
   |                                 ^^^^^^^^^^^^^^^^
   |
   = note: JSON pointer: /definition/actions/Call/type
```

Terminal output uses color when stdout is a terminal. Piped output and sessions
with `NO_COLOR` set use plain text.

## JSON Output

`--format json` emits a stable diagnostic contract:

```json
[
  {
    "code": "unknown-action-reference",
    "severity": "error",
    "path": "Workflow/workflow.json",
    "pointer": "/definition/actions/Compose/inputs",
    "message": "WDL expression references missing action 'Missing'"
  }
]
```

JSON output includes the human message so automation can distinguish multiple
diagnostics with the same code and pointer. Line numbers are intentionally
excluded; use `path` and `pointer` as the stable location keys, and include
`code` plus `message` when automation needs to distinguish multiple diagnostics
at the same location.

## Exit Codes

- `0`: no error diagnostics (warnings do not fail exit)
- `1`: one or more error diagnostics
- `2`: tool usage, IO, or walking error

## Library

The crate also exposes a small library API for embedding the linter:

```rust
use logicapps_lint::{lint_path, Diagnostic, LintError};

fn main() -> Result<(), LintError> {
    let diagnostics: Vec<Diagnostic> = lint_path("path/to/project")?;
    for diagnostic in &diagnostics {
        println!("{}: {}", diagnostic.code, diagnostic.message);
    }
    Ok(())
}
```

`--warn` / `--allow` are CLI concerns; library callers receive raw diagnostics
and can filter or reclassify them themselves.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your
option.
