//! Central policy table for the `--strict` / default (lenient) split.
//!
//! Rules always emit their "strict" diagnostic. This module then relaxes the
//! collected set for lenient callers by (a) dropping diagnostics whose only
//! sin is case divergence from a runtime-tolerated enum, and (b) downgrading
//! registry-gap diagnostics (unknown action/trigger type, unregistered kind,
//! unregistered `operationOptions` token) to warnings.
//!
//! Post-processing is used instead of threading a `strict: bool` through
//! every rule module because:
//!  * exactly one place decides the strict-vs-lenient contract, so tests
//!    and future audits have a single point of truth;
//!  * rule modules stay policy-free and continue to emit maximally strict
//!    diagnostics regardless of caller;
//!  * the fallout of a wording tweak is contained here.
//!
//! The tradeoff is that this module reads diagnostic messages as an
//! internal contract. `extract_first_quoted_token` and the case lists
//! below are the only surface that couples to the wording; any rule that
//! rewords one of the relaxed messages must update this file.
//!
//! # Under lenient mode
//!
//! The Azure Logic Apps runtime accepts several enum values in ways the
//! documented schema does not. Rather than teach every rule to know this,
//! the runtime-tolerated case variants are dropped here:
//!
//! * `runafter-invalid-status` for `SUCCEEDED`/`FAILED`/`SKIPPED`/`TIMEDOUT`
//!   (any case, `Succeeded`/`Failed`/`Skipped`/`TimedOut` schema literals
//!   still pass through the underlying rule);
//! * `workflow-shape-invalid-value` for `definition parameter type` where
//!   the token is a case variant of a known primitive
//!   (`string`/`int`/`bool`/...).
//!
//! And the registry-gap diagnostics — where the linter's action/trigger
//! registry, kind allow-list, or `operationOptions` allow-list has fallen
//! behind Logic Apps' evolving surface area — are downgraded to warnings
//! so they surface without failing the run:
//!
//! * `workflow-shape-unknown-type` (unknown action or trigger `type`);
//! * `workflow-shape-invalid-value` for `kind '...'` and
//!   `operationOptions '...'` messages.
//!
//! Structural `workflow-shape-invalid-value` diagnostics (`must contain at
//! least one trigger`, `name exceeds ... limit`, etc.) are always kept as
//! errors because their message shape does not match any of the runtime-
//! tolerance patterns above.

use crate::diagnostic::{Diagnostic, Severity};

/// Apply the strict/lenient policy to a diagnostic set.
///
/// `strict = true` returns the input unchanged. `strict = false` drops
/// runtime-tolerated case variants and downgrades registry-gap diagnostics
/// to `Severity::Warning`. See the module docs for the exact table.
pub fn relax_diagnostics(diagnostics: Vec<Diagnostic>, strict: bool) -> Vec<Diagnostic> {
    if strict {
        return diagnostics;
    }
    diagnostics
        .into_iter()
        .filter_map(relax_diagnostic)
        .collect()
}

fn relax_diagnostic(mut diagnostic: Diagnostic) -> Option<Diagnostic> {
    match diagnostic.code.as_str() {
        "runafter-invalid-status" => {
            if is_case_variant_of_runafter_status(&diagnostic.message) {
                return None;
            }
            Some(diagnostic)
        }
        "workflow-shape-unknown-type" => {
            diagnostic.severity = Severity::Warning;
            Some(diagnostic)
        }
        "workflow-shape-invalid-value" => {
            if is_parameter_type_case_variant(&diagnostic.message) {
                return None;
            }
            if is_registry_gap_invalid_value(&diagnostic.message) {
                diagnostic.severity = Severity::Warning;
            }
            Some(diagnostic)
        }
        _ => Some(diagnostic),
    }
}

/// The four `runAfter` status literals as they appear in the documented
/// schema. Anything that matches one of these case-insensitively is treated
/// as a runtime-accepted case variant.
const RUNAFTER_STATUS_LITERALS: &[&str] = &["Succeeded", "Failed", "Skipped", "TimedOut"];

fn is_case_variant_of_runafter_status(message: &str) -> bool {
    let Some(token) = extract_first_quoted_token(message) else {
        return false;
    };
    RUNAFTER_STATUS_LITERALS
        .iter()
        .any(|literal| literal.eq_ignore_ascii_case(token))
}

/// Primitive parameter type names as documented for `definition.parameters`.
/// Both the WDL and template-manifest spellings are listed so a template that
/// declares `type: "SecureObject"` in lower case still relaxes cleanly.
const PARAMETER_TYPE_LITERALS: &[&str] = &[
    "String",
    "SecureString",
    "Int",
    "Integer",
    "Float",
    "Bool",
    "Boolean",
    "Array",
    "Object",
    "SecureObject",
];

fn is_parameter_type_case_variant(message: &str) -> bool {
    if !message.starts_with("definition parameter type ") {
        return false;
    }
    let Some(token) = extract_first_quoted_token(message) else {
        return false;
    };
    PARAMETER_TYPE_LITERALS
        .iter()
        .any(|literal| literal.eq_ignore_ascii_case(token))
}

/// Registry gaps show up as `<something> kind '...' is not supported` or
/// `action operationOptions '...' is not supported` — the linter's
/// registry has simply not caught up with a newer Logic Apps release.
/// Structural messages (`must contain at least one trigger`, `... exceeds
/// the 32 character limit`) do not match this shape and stay as errors.
fn is_registry_gap_invalid_value(message: &str) -> bool {
    message.contains(" kind '") && message.ends_with("' is not supported")
        || message.starts_with("action operationOptions '")
            && message.ends_with("' is not supported")
}

/// Extract the substring between the first pair of single quotes.
/// Returns `None` if either quote is missing. The diagnostic messages this
/// module inspects all embed the offending literal between single quotes,
/// so the first pair is sufficient.
fn extract_first_quoted_token(message: &str) -> Option<&str> {
    let start = message.find('\'')?;
    let after_open = start + 1;
    let end_offset = message[after_open..].find('\'')?;
    Some(&message[after_open..after_open + end_offset])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Diagnostic;
    use std::path::PathBuf;

    fn diag(code: &str, message: &str) -> Diagnostic {
        Diagnostic::error(
            code,
            PathBuf::from("test.json"),
            "".to_owned(),
            None,
            message,
        )
    }

    #[test]
    fn strict_mode_passes_diagnostics_through() {
        let input = vec![diag(
            "runafter-invalid-status",
            "runAfter status 'SUCCEEDED' is not supported",
        )];
        let out = relax_diagnostics(input, true);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Error);
    }

    #[test]
    fn lenient_drops_runafter_case_variants() {
        for variant in ["SUCCEEDED", "succeeded", "Succeeded", "sUcCeEdEd"] {
            let msg = format!("runAfter status '{variant}' is not supported");
            let out = relax_diagnostics(vec![diag("runafter-invalid-status", &msg)], false);
            assert!(out.is_empty(), "variant {variant:?} should be dropped");
        }
        for variant in ["FAILED", "SKIPPED", "TIMEDOUT", "TIMEdOUT"] {
            let msg = format!("runAfter status '{variant}' is not supported");
            let out = relax_diagnostics(vec![diag("runafter-invalid-status", &msg)], false);
            assert!(out.is_empty(), "variant {variant:?} should be dropped");
        }
    }

    #[test]
    fn lenient_keeps_genuinely_unknown_runafter_status() {
        let msg = "runAfter status 'DONE' is not supported";
        let out = relax_diagnostics(vec![diag("runafter-invalid-status", msg)], false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Error);
    }

    #[test]
    fn lenient_downgrades_unknown_type() {
        let msg = "unknown action type 'ChunkText'";
        let out = relax_diagnostics(vec![diag("workflow-shape-unknown-type", msg)], false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Warning);
    }

    #[test]
    fn lenient_drops_parameter_type_case_variants() {
        for variant in [
            "string",
            "int",
            "integer",
            "bool",
            "boolean",
            "SECUREOBJECT",
        ] {
            let msg = format!("definition parameter type '{variant}' is not supported");
            let out = relax_diagnostics(vec![diag("workflow-shape-invalid-value", &msg)], false);
            assert!(out.is_empty(), "variant {variant:?} should be dropped");
        }
    }

    #[test]
    fn lenient_downgrades_registry_gap_kinds() {
        for msg in [
            "workflow kind 'Agentic' is not supported",
            "trigger kind 'Polling' is not supported",
            "action kind 'DataMapper' is not supported",
            "action operationOptions 'Asynchronous' is not supported",
        ] {
            let out = relax_diagnostics(vec![diag("workflow-shape-invalid-value", msg)], false);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].severity, Severity::Warning, "{msg}");
        }
    }

    #[test]
    fn lenient_keeps_structural_invalid_value_as_error() {
        for msg in [
            "definition.triggers must contain at least one trigger",
            "Standard workflow name 'x' exceeds the 32 character limit",
        ] {
            let out = relax_diagnostics(vec![diag("workflow-shape-invalid-value", msg)], false);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].severity, Severity::Error, "{msg}");
        }
    }

    #[test]
    fn lenient_passes_unrelated_codes_through() {
        let out = relax_diagnostics(vec![diag("wdl-syntax-error", "unclosed literal")], false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Error);
    }
}
