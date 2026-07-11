//! Shallow scanner for the Workflow Definition Language (WDL) expression
//! subset used by Azure Logic Apps.
//!
//! WDL values reach this module as JSON strings that either start with a
//! leading `@` (a "full expression") or embed one or more `@{...}`
//! interpolations inside plain text. A leading `@@` escapes the `@` back to
//! a literal, and inside expressions single quotes delimit string literals
//! (with `''` escaping a single quote). ARM templates may embed WDL inside
//! their own single-quoted strings, so quotes can arrive already doubled.
//!
//! The scanner is deliberately shallow: it does not build an AST. Instead it
//! extracts just enough structure — reference calls, function-call names,
//! syntax errors — for downstream rules in `src/check/` to reason about
//! workflow validity without depending on the runtime evaluator. Anything
//! that requires real semantic evaluation is left to the runtime.
//!
//! Public entry points are re-exported at the bottom of this file; consumer
//! modules should call those rather than the individual submodules.

#[derive(Debug, Clone, PartialEq, Eq)]
/// A statically resolvable WDL reference found in an expression string.
///
/// Only calls whose first argument is a literal string are captured here; a
/// call like `outputs(variables('x'))` is intentionally skipped because its
/// target cannot be resolved without evaluation.
pub struct Reference {
    /// Reference family; this decides which workflow namespace is checked.
    pub kind: ReferenceKind,
    /// Literal first argument to the reference function.
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A syntax issue found by the shallow WDL scanner.
pub struct SyntaxIssue {
    /// Human-readable message suitable for diagnostics.
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Function call metadata used by policy checks that do not need a full AST.
pub struct FunctionCall {
    /// Function identifier as it appears in the expression.
    pub name: String,
    /// Whether the identifier was followed by a parenthesized call.
    pub parenthesized: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Static reference namespace represented by a WDL helper function.
///
/// The variants map one-to-one onto the workflow lookup table a rule needs
/// to consult when validating the reference target (actions, parameters,
/// variables, foreach items, and so on).
pub enum ReferenceKind {
    /// Action-output helpers such as `outputs('A')`, `body('A')`, and multipart helpers.
    Action,
    /// Current item helper `item()`, scoped by Foreach or data-operation fields.
    CurrentItem,
    /// Scoped action helper `result('Scope')`.
    ScopedAction,
    /// Until loop helper `iterationIndexes('Loop')`.
    UntilLoop,
    /// Workflow variable helper `variables('name')`.
    Variable,
    /// Workflow parameter helper `parameters('name')`.
    Parameter,
    /// Named loop item helper `items('Foreach')`.
    Item,
}

mod arity;
mod functions;
mod lex;
mod references;
mod segments;
mod syntax;
mod value;

pub use functions::{
    function_call_suffixes_in_string, function_calls_in_string,
    string_arg_function_call_suffixes_in_string, zero_arg_function_call_in_string,
    zero_arg_function_call_suffixes_in_string,
};
pub use references::references_in_string;
pub use syntax::syntax_issues_in_string;
pub(crate) use value::{WdlStringTemplate, WdlStringValue};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_escaped_at() {
        assert!(references_in_string("@@{outputs('A')}").is_empty());
    }

    #[test]
    fn extracts_interpolation() {
        let refs = references_in_string("prefix @{outputs('A')?['body']} suffix");
        assert_eq!(refs[0].name, "A");
    }

    #[test]
    fn extracts_action_scoped_and_loop_reference_functions() {
        let refs = references_in_string(
            "@concat(formDataValue('FormAction', 'subject'), multipartBody('MultipartAction', 0), result('ScopeAction'), iterationIndexes('UntilAction'))",
        );
        assert_eq!(
            refs,
            vec![
                Reference {
                    kind: ReferenceKind::Action,
                    name: "FormAction".to_owned(),
                },
                Reference {
                    kind: ReferenceKind::Action,
                    name: "MultipartAction".to_owned(),
                },
                Reference {
                    kind: ReferenceKind::ScopedAction,
                    name: "ScopeAction".to_owned(),
                },
                Reference {
                    kind: ReferenceKind::UntilLoop,
                    name: "UntilAction".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn extracts_multiple_interpolations() {
        let refs = references_in_string("@{outputs('A')} and @{body('B')}");
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].name, "A");
        assert_eq!(refs[1].name, "B");
    }

    #[test]
    fn escaped_leading_at_does_not_disable_later_interpolation() {
        let refs = references_in_string("@@literal @{outputs('A')}");
        assert_eq!(refs[0].name, "A");
    }

    #[test]
    fn escaped_interpolation_is_literal_inside_plain_text() {
        assert!(references_in_string("literal @@{outputs('Missing')}").is_empty());
        assert!(syntax_issues_in_string("literal @@{outputs('Missing')}").is_empty());
    }

    #[test]
    fn root_expression_string_literals_are_not_interpolations() {
        assert!(syntax_issues_in_string("@concat('literal @{ without close', 'ok')").is_empty());
    }

    #[test]
    fn handles_escaped_single_quote() {
        let refs = references_in_string("@parameters('it''s')");
        assert_eq!(refs[0].name, "it's");
    }

    #[test]
    fn ignores_calls_inside_string_literals() {
        let refs = references_in_string("@concat('outputs(''Fake'')', outputs('Real'))");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "Real");
    }

    #[test]
    fn extracts_arm_escaped_string_arguments() {
        let refs = references_in_string("@{encodeURIComponent(body(''Create_job'')?[''id''])}");
        assert_eq!(refs[0].name, "Create_job");
    }

    #[test]
    fn extracts_utf8_string_arguments() {
        let refs = references_in_string("@body('BLOB_コンテンツを取得する_(V2)')");
        assert_eq!(refs[0].name, "BLOB_コンテンツを取得する_(V2)");
    }

    #[test]
    fn extracts_function_calls_for_project_expression_policy() {
        let calls = function_calls_in_string("@concat(parameters('name'), appsetting('SETTING'))");
        let names: Vec<_> = calls.into_iter().map(|call| call.name).collect();
        assert_eq!(names, vec!["concat", "parameters", "appsetting"]);
    }

    #[test]
    fn extracts_bare_root_identifier_for_project_expression_policy() {
        let calls = function_calls_in_string("@variables");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "variables");
        assert!(!calls[0].parenthesized);
    }

    #[test]
    fn extracts_bare_root_identifier_even_with_nested_calls() {
        let calls = function_calls_in_string("@variables + appsetting('SETTING')");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "appsetting");
        assert!(calls[0].parenthesized);
        assert_eq!(calls[1].name, "variables");
        assert!(!calls[1].parenthesized);
    }

    #[test]
    fn reports_unclosed_interpolation() {
        let issues = syntax_issues_in_string("prefix @{outputs('A')");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn reports_unclosed_string_literal() {
        let issues = syntax_issues_in_string("@concat('open)");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn reports_unclosed_string_literal_after_escaped_quote() {
        let issues = syntax_issues_in_string("@concat('open'')");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn reports_root_expression_plain_text_suffix() {
        let issues = syntax_issues_in_string("@parameters('name')/suffix");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn reports_reference_function_arity() {
        let issues = syntax_issues_in_string("@outputs('A', 'extra')");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expects 1 argument"));
    }

    #[test]
    fn reports_concat_minimum_arity() {
        let issues = syntax_issues_in_string("@concat('one')");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expects at least 2 argument"));

        assert!(syntax_issues_in_string("@concat('one', 'two')").is_empty());
    }

    #[test]
    fn reports_malformed_reference_arguments_without_panicking() {
        let issues = syntax_issues_in_string("@outputs('A'])");
        assert!(!issues.is_empty());
        assert!(issues.iter().any(
            |issue| issue.message.contains("malformed") || issue.message.contains("mismatched")
        ));
    }

    #[test]
    fn reports_empty_reference_arguments() {
        for expression in [
            "@outputs(,)",
            "@formDataValue('A',,)",
            "@triggerFormDataValue(,)",
        ] {
            let issues = syntax_issues_in_string(expression);
            assert!(
                issues
                    .iter()
                    .any(|issue| issue.message.contains("empty argument")),
                "{expression}: {issues:?}"
            );
        }
    }

    #[test]
    fn allows_nested_reference_function_argument() {
        let issues = syntax_issues_in_string("@outputs(parameters('ActionName'))");
        assert!(issues.is_empty());
    }

    #[test]
    fn reports_item_function_arity() {
        let issues = syntax_issues_in_string("@item('unexpected')");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expects 0 argument"));
    }

    #[test]
    fn reports_action_function_arity() {
        let issues = syntax_issues_in_string("@action('unexpected')");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expects 0 argument"));
    }

    #[test]
    fn detects_zero_arg_function_calls_with_spacing() {
        assert!(zero_arg_function_call_in_string("@action ()", "action"));
        assert!(!zero_arg_function_call_in_string(
            "@action('unexpected')",
            "action"
        ));
    }

    #[test]
    fn reports_list_callback_url_function_arity() {
        let issues = syntax_issues_in_string("@listCallbackUrl('unexpected')");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expects 0 argument"));
    }

    #[test]
    fn reports_zero_arg_workflow_function_arity() {
        let issues = syntax_issues_in_string("@triggerBody('unexpected')");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expects 0 argument"));

        let issues = syntax_issues_in_string("@workflow('unexpected')");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expects 0 argument"));
    }

    #[test]
    fn reports_trigger_helper_function_arity() {
        let issues = syntax_issues_in_string("@trigger('unexpected')");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expects 0 argument"));

        let issues = syntax_issues_in_string("@triggerOutputs('unexpected')");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expects 0 argument"));

        let issues = syntax_issues_in_string("@triggerFormDataValue()");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expects 1 argument"));

        let issues = syntax_issues_in_string("@triggerMultipartBody()");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expects 1 argument"));
    }

    #[test]
    fn reports_appsetting_function_arity() {
        let issues = syntax_issues_in_string("@appsetting()");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("expects 1 argument"));
    }

    #[test]
    fn reports_unbraced_expression_inside_plain_text() {
        let issues = syntax_issues_in_string("/subscriptions/@appsetting('SUBSCRIPTION_ID')");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("plain text"));
    }

    #[test]
    fn ignores_escaped_unbraced_expression_inside_plain_text() {
        assert!(syntax_issues_in_string("@@appsetting('SUBSCRIPTION_ID')").is_empty());
    }

    #[test]
    fn allows_root_expression_accessors() {
        assert!(syntax_issues_in_string("@outputs('A')?['body'].value").is_empty());
        assert!(syntax_issues_in_string("@trigger().outputs?.body").is_empty());
    }
}
