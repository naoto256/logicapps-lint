//! Human-facing diagnostic renderer backed by `annotate-snippets`.
//!
//! Handles both [`Severity::Error`] and [`Severity::Warning`] output, picks
//! color vs. plain styling from the TTY state and `NO_COLOR`, and lazily reads
//! each referenced source file exactly once so span-carrying diagnostics can
//! print inline snippets without re-parsing.

use annotate_snippets::{
    AnnotationKind, Level, Origin, Renderer, Snippet, normalize_untrusted_str,
};
use logicapps_lint::{ByteSpan, Diagnostic, Severity, display_path, sanitize_for_terminal};
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::ops::Range;
use std::path::Path;

/// Print `diagnostics` to stdout in the human format, resolving paths relative
/// to `base`. Emits a friendly "no issues" line when the slice is empty and
/// separates successive diagnostics with a blank line for readability.
pub(crate) fn print(base: &Path, diagnostics: &[Diagnostic]) {
    if diagnostics.is_empty() {
        println!("No Logic Apps workflow issues found.");
        return;
    }

    let renderer = terminal_renderer();
    let mut source_cache = BTreeMap::new();
    for (index, diagnostic) in diagnostics.iter().enumerate() {
        let path = sanitize_for_terminal(&display_path(base, &diagnostic.path));
        let source = if diagnostic.span.is_some() {
            source_cache
                .entry(diagnostic.path.clone())
                .or_insert_with(|| std::fs::read_to_string(&diagnostic.path).ok())
                .as_deref()
        } else {
            None
        };
        println!(
            "{}",
            render_diagnostic(&renderer, diagnostic, &path, source)
        );
        if index + 1 < diagnostics.len() {
            println!();
        }
    }
}

fn terminal_renderer() -> Renderer {
    if std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() {
        Renderer::styled()
    } else {
        Renderer::plain()
    }
}

fn render_diagnostic(
    renderer: &Renderer,
    diagnostic: &Diagnostic,
    path: &str,
    source: Option<&str>,
) -> String {
    let level = diagnostic_level(diagnostic.severity);
    let title = level
        .primary_title(&diagnostic.message)
        .id(&diagnostic.code);
    let primary = match (source, diagnostic.span) {
        (Some(source), Some(span)) => match normalized_span(source, span) {
            Some(span) => title.element(
                Snippet::source(source)
                    .path(path)
                    .fold(true)
                    .annotation(AnnotationKind::Primary.span(span)),
            ),
            None => title.element(Origin::path(path)),
        },
        _ => title.element(Origin::path(path)),
    };

    let primary = if diagnostic.pointer.is_empty() {
        primary
    } else {
        let pointer = normalize_untrusted_str(&format!("JSON pointer: {}", diagnostic.pointer));
        primary.element(Level::NOTE.message(pointer))
    };
    let report = [primary];
    renderer.render(&report).to_string()
}

fn diagnostic_level(severity: Severity) -> Level<'static> {
    match severity {
        Severity::Error => Level::ERROR,
        Severity::Warning => Level::WARNING,
    }
}

/// Clamp `span` to the file's byte length and snap it out to the nearest UTF-8
/// character boundaries so `annotate-snippets` never slices mid-codepoint.
///
/// Returns `None` for empty sources or collapsed ranges. Widening (rather than
/// narrowing) the span preserves the original byte offsets emitted by the JSON
/// parser even when a diagnostic points at a value containing multi-byte text.
fn normalized_span(source: &str, span: ByteSpan) -> Option<Range<usize>> {
    if source.is_empty() {
        return None;
    }
    let mut start = span.start.min(source.len());
    while start > 0 && !source.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = span.end.min(source.len()).max(start);
    while end < source.len() && !source.is_char_boundary(end) {
        end += 1;
    }
    (start < end).then_some(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn renders_source_span_and_json_pointer() {
        let source = "{\n  \"type\": \"InvokeWorkflow\"\n}\n";
        let start = source.find("InvokeWorkflow").expect("fixture text");
        let diagnostic = Diagnostic::error(
            "workflow-shape-unknown-type",
            PathBuf::from("workflow.json"),
            "/actions/Call/type",
            Some(ByteSpan {
                start,
                end: start + "InvokeWorkflow".len(),
            }),
            "unknown action type 'InvokeWorkflow'",
        );

        let rendered = render_diagnostic(
            &Renderer::plain(),
            &diagnostic,
            "workflow.json",
            Some(source),
        );

        assert!(
            rendered.contains(
                "error[workflow-shape-unknown-type]: unknown action type 'InvokeWorkflow'"
            )
        );
        assert!(rendered.contains("--> workflow.json:2:12"));
        assert!(rendered.contains("^"));
        assert!(rendered.contains("= note: JSON pointer: /actions/Call/type"));
    }

    #[test]
    fn renders_path_without_source_span() {
        let diagnostic = Diagnostic::error(
            "workflow-shape-invalid-value",
            PathBuf::from("LongName/workflow.json"),
            "",
            None,
            "workflow name is too long",
        );

        let rendered = render_diagnostic(
            &Renderer::plain(),
            &diagnostic,
            "LongName/workflow.json",
            None,
        );

        assert!(rendered.contains("error[workflow-shape-invalid-value]"));
        assert!(rendered.contains("--> LongName/workflow.json"));
        assert!(!rendered.contains("JSON pointer"));
    }
}
