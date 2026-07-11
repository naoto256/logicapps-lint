use logicapps_lint::Severity;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
struct ExpectedDiagnostic {
    code: String,
    severity: Severity,
    path: String,
    pointer: String,
}

#[test]
fn fixture_corpus_matches_expected_diagnostics() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut cases = discover_cases(&root);
    cases.sort();
    assert!(!cases.is_empty(), "fixture corpus must not be empty");

    for case in cases {
        // expected.json is the --format json contract, deliberately excluding
        // messages and line numbers so wording/layout improvements do not
        // rewrite the corpus.
        let expected_path = case.join("expected.json");
        let expected: Vec<ExpectedDiagnostic> =
            serde_json::from_str(&std::fs::read_to_string(&expected_path).unwrap())
                .unwrap_or_else(|error| panic!("{}: {error}", expected_path.display()));

        // The corpus documents the full rule set: every registered check firing
        // literally, without runtime-tolerance relaxations. `--strict` is the
        // mode that matches that contract, so the harness always passes it.
        // Lenient-mode behavior is exercised by dedicated tests in `tests/cli.rs`.
        let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
            .arg(&case)
            .arg("--format")
            .arg("json")
            .arg("--strict")
            .output()
            .unwrap_or_else(|error| panic!("{}: {error}", case.display()));
        let expected_status = if expected
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
        {
            1
        } else {
            0
        };
        assert_eq!(
            output.status.code(),
            Some(expected_status),
            "fixture {} stderr: {}",
            case.display(),
            String::from_utf8_lossy(&output.stderr)
        );

        let mut actual: Vec<ExpectedDiagnostic> = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| {
                panic!(
                    "{}: {error}; stdout: {}",
                    case.display(),
                    String::from_utf8_lossy(&output.stdout)
                )
            });
        actual.sort();

        let mut expected = expected;
        expected.sort();
        assert_eq!(actual, expected, "fixture {}", case.display());
    }
}

fn discover_cases(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file() && entry.file_name() == "expected.json")
        .filter_map(|entry| entry.path().parent().map(Path::to_path_buf))
        .collect()
}
