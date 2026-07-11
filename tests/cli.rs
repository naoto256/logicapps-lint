use std::fmt::Write as _;
use std::process::Command;

#[test]
fn json_output_uses_input_relative_paths() {
    let fixture = fixture_path("project/connections_reference_missing");
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"path\": \"connections_reference_missing/workflow.json\""));
    assert!(!stdout.contains("tests/fixtures"));
}

#[test]
fn clean_input_exits_zero() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let fixture = std::env::temp_dir().join(format!(
        "logicapps-lint-clean-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&fixture).expect("create clean fixture dir");
    std::fs::write(fixture.join("workflow.json"), CLEAN_WORKFLOW).expect("write workflow");
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&fixture);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[test]
fn invalid_utf8_workflow_reports_json_parse_error() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let fixture = std::env::temp_dir().join(format!(
        "logicapps-lint-invalid-utf8-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&fixture).expect("create invalid utf8 fixture dir");
    std::fs::write(fixture.join("workflow.json"), [0xff]).expect("write invalid utf8 workflow");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&fixture);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let diagnostics: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("json diagnostics");
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0]["code"], "json-parse-error");
}

#[test]
fn json_format_usage_errors_use_json_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg("--format")
        .arg("json")
        .arg("--definitely-not-a-real-flag")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let diagnostics: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("json diagnostics");
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0]["code"], "tool-error");
    assert_eq!(diagnostics[0]["severity"], "error");
    assert_eq!(diagnostics[0]["path"], ".");
}

#[test]
fn json_usage_errors_redact_absolute_path_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg("--format")
        .arg("json")
        .arg(".")
        .arg("/tmp/logicapps-lint-secret-root/workflow.json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let diagnostics: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("json diagnostics");
    let message = diagnostics[0]["message"].as_str().unwrap();
    assert!(message.contains("'<path>'"));
    assert!(!message.contains("/tmp/logicapps-lint-secret-root"));
}

#[test]
fn json_usage_errors_redact_apostrophe_absolute_path_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg("--format")
        .arg("json")
        .arg(".")
        .arg("/tmp/audit' found\nsecret-token/workflow.json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let diagnostics: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("json diagnostics");
    let message = diagnostics[0]["message"].as_str().unwrap();
    assert!(message.contains("'<path>'"));
    assert!(!message.contains("/tmp/audit"));
    assert!(!message.contains("secret-token"));
}

#[test]
fn json_usage_errors_redact_embedded_absolute_path_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg("--format")
        .arg("json")
        .arg(".")
        .arg("x=/tmp/logicapps-lint-secret-root/workflow.json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let diagnostics: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("json diagnostics");
    let message = diagnostics[0]["message"].as_str().unwrap();
    assert!(message.contains("x=<path>"));
    assert!(!message.contains("/tmp/logicapps-lint-secret-root"));
}

#[test]
fn json_usage_errors_redact_windows_absolute_path_arguments() {
    for (argument, secret) in [
        (
            r"C:\Users\alice\logicapps-lint-secret\workflow.json",
            r"C:\Users\alice",
        ),
        (
            r"x=C:\Users\alice\logicapps-lint-secret\workflow.json",
            r"C:\Users\alice",
        ),
        (
            r"\\private-server\secret-share\workflow.json",
            r"\\private-server\secret-share",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
            .arg("--format")
            .arg("json")
            .arg(".")
            .arg(argument)
            .output()
            .expect("run logicapps-lint");

        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let diagnostics: Vec<serde_json::Value> =
            serde_json::from_slice(&output.stdout).expect("json diagnostics");
        let message = diagnostics[0]["message"].as_str().unwrap();
        assert!(message.contains("<path>"));
        assert!(!message.contains(secret));
    }
}

#[test]
fn option_terminator_prevents_json_format_detection() {
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg("--")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("unexpected argument 'json'"));
    assert!(!stderr.contains("\"code\": \"tool-error\""));
}

#[test]
fn help_and_version_exit_successfully() {
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["--format", "json", "--help"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
            .args(args)
            .output()
            .expect("run logicapps-lint");

        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(stdout.contains("logicapps-lint"));
        assert!(!stdout.contains("\"code\": \"tool-error\""));
    }
}

#[test]
fn no_args_ignores_generated_target_tree() {
    let fixture = fixture_path("parse/target-dir-ignored");
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .current_dir(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"code\": \"no-workflows-found\""));
    assert!(!stdout.contains("Generated_Invalid"));
}

#[test]
fn explicit_target_directory_is_scanned() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-explicit-target-{}-{unique}",
        std::process::id()
    ));
    let target_dir = root.join("target");
    std::fs::create_dir_all(&target_dir).expect("create target dir");
    std::fs::write(target_dir.join("workflow.json"), CLEAN_WORKFLOW).expect("write workflow");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&target_dir)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn symlink_to_target_directory_is_ignored_during_directory_scan() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-symlink-target-{}-{unique}",
        std::process::id()
    ));
    let target_workflow_dir = root.join("target").join("package").join("Main");
    std::fs::create_dir_all(&target_workflow_dir).expect("create generated target workflow dir");
    std::fs::write(root.join("workflow.json"), CLEAN_WORKFLOW).expect("write clean workflow");
    std::fs::write(
        target_workflow_dir.join("workflow.json"),
        r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {
      "Use": {
        "type": "Compose",
        "inputs": "@outputs('Generated_Invalid')",
        "runAfter": {}
      }
    },
    "outputs": {}
  },
  "kind": "Stateful"
}
"#,
    )
    .expect("write generated invalid workflow");
    std::os::unix::fs::symlink(root.join("target"), root.join("linked"))
        .expect("create target symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn symlink_to_target_workflow_file_is_ignored_during_directory_scan() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-symlink-target-file-{}-{unique}",
        std::process::id()
    ));
    let target_workflow_dir = root.join("target").join("package").join("Main");
    let link_dir = root.join("Main");
    std::fs::create_dir_all(&target_workflow_dir).expect("create generated target workflow dir");
    std::fs::create_dir_all(&link_dir).expect("create workflow link dir");
    std::fs::write(root.join("workflow.json"), CLEAN_WORKFLOW).expect("write clean workflow");
    std::fs::write(
        target_workflow_dir.join("workflow.json"),
        r#"{
  "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
  "contentVersion": "1.0.0.0",
  "triggers": {
    "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
  },
  "actions": {
    "Use": {
      "type": "Compose",
      "inputs": "@outputs('Generated_Invalid')",
      "runAfter": {}
    }
  },
  "outputs": {}
}
"#,
    )
    .expect("write generated invalid workflow");
    std::os::unix::fs::symlink(
        target_workflow_dir.join("workflow.json"),
        link_dir.join("workflow.json"),
    )
    .expect("create target workflow file symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn symlink_to_external_target_directory_is_ignored_during_directory_scan() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-external-target-root-{}-{unique}",
        std::process::id()
    ));
    let external = std::env::temp_dir().join(format!(
        "logicapps-lint-external-target-{}-{unique}",
        std::process::id()
    ));
    let target_workflow_dir = external.join("target").join("package").join("Main");
    std::fs::create_dir_all(&root).expect("create scan root");
    std::fs::create_dir_all(&target_workflow_dir).expect("create generated target workflow dir");
    std::fs::write(root.join("workflow.json"), CLEAN_WORKFLOW).expect("write clean workflow");
    std::fs::write(
        target_workflow_dir.join("workflow.json"),
        r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {
      "Use": {
        "type": "Compose",
        "inputs": "@outputs('Generated_Invalid')",
        "runAfter": {}
      }
    },
    "outputs": {}
  },
  "kind": "Stateful"
}
"#,
    )
    .expect("write generated invalid workflow");
    std::os::unix::fs::symlink(external.join("target"), root.join("linked"))
        .expect("create target symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&external);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn symlinked_workflow_file_is_scanned() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-symlink-workflow-{}-{unique}",
        std::process::id()
    ));
    let real_dir = root.join("Real");
    let link_dir = root.join("Main");
    std::fs::create_dir_all(&real_dir).expect("create real dir");
    std::fs::create_dir_all(&link_dir).expect("create link dir");
    let real_workflow = real_dir.join("workflow.json");
    std::fs::write(&real_workflow, CLEAN_WORKFLOW).expect("write workflow");
    std::os::unix::fs::symlink(&real_workflow, link_dir.join("workflow.json"))
        .expect("create workflow symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn symlinked_workflow_directory_is_scanned() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-symlink-workflow-dir-{}-{unique}",
        std::process::id()
    ));
    let scan_root = root.join("Scan");
    let real_workflow_dir = scan_root.join("Real").join("Bad");
    std::fs::create_dir_all(&scan_root).expect("create scan root");
    std::fs::create_dir_all(&real_workflow_dir).expect("create real workflow dir");
    std::fs::write(
        real_workflow_dir.join("workflow.json"),
        r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {
      "Use": {
        "type": "Compose",
        "inputs": "@outputs('Missing')",
        "runAfter": {}
      }
    }
  },
  "kind": "Stateful"
}
"#,
    )
    .expect("write workflow");
    std::os::unix::fs::symlink(scan_root.join("Real"), scan_root.join("Linked"))
        .expect("create workflow directory symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&scan_root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"code\": \"unknown-action-reference\""));
    assert!(stdout.contains("\"path\": \"Linked/Bad/workflow.json\""));
}

#[cfg(unix)]
#[test]
fn symlink_to_external_workflow_directory_is_ignored_during_directory_scan() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-external-workflow-root-{}-{unique}",
        std::process::id()
    ));
    let external = std::env::temp_dir().join(format!(
        "logicapps-lint-external-workflow-{}-{unique}",
        std::process::id()
    ));
    let scan_root = root.join("scan");
    let external_workflow_dir = external.join("Bad");
    std::fs::create_dir_all(&scan_root).expect("create scan root");
    std::fs::create_dir_all(&external_workflow_dir).expect("create external workflow dir");
    std::fs::write(scan_root.join("workflow.json"), CLEAN_WORKFLOW).expect("write clean workflow");
    std::fs::write(
        external_workflow_dir.join("workflow.json"),
        r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {
      "Bad": { "type": "NoSuchAction", "runAfter": {} }
    },
    "outputs": {}
  },
  "kind": "Stateful"
}
"#,
    )
    .expect("write external invalid workflow");
    std::os::unix::fs::symlink(&external, scan_root.join("Linked"))
        .expect("create external workflow directory symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&scan_root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&external);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn symlink_to_external_project_sidecar_is_ignored_during_directory_scan() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-external-sidecar-root-{}-{unique}",
        std::process::id()
    ));
    let external = std::env::temp_dir().join(format!(
        "logicapps-lint-external-sidecar-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("Main");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::fs::create_dir_all(&external).expect("create external sidecar dir");
    std::fs::write(root.join("host.json"), r#"{ "version": "2.0" }"#).expect("write host");
    std::fs::write(workflow_dir.join("workflow.json"), CLEAN_WORKFLOW).expect("write workflow");
    std::fs::write(
        external.join("parameters.json"),
        r#"{ "queueName": { "value": "outside" } }"#,
    )
    .expect("write external invalid sidecar");
    std::os::unix::fs::symlink(
        external.join("parameters.json"),
        root.join("parameters.json"),
    )
    .expect("create external sidecar symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&external);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn external_sidecar_symlink_does_not_mark_standard_project() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-marker-sidecar-root-{}-{unique}",
        std::process::id()
    ));
    let external = std::env::temp_dir().join(format!(
        "logicapps-lint-marker-sidecar-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("Main");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::fs::create_dir_all(&external).expect("create external sidecar dir");
    std::fs::write(
        workflow_dir.join("workflow.json"),
        r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
      "NeedsValue": {
        "type": "String",
        "defaultValue": "fallback"
      }
    },
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {}
  },
  "kind": "Stateful"
}"#,
    )
    .expect("write workflow");
    std::fs::write(external.join("parameters.json"), r#"{ "parameters": {} }"#)
        .expect("write external sidecar");
    std::os::unix::fs::symlink(
        external.join("parameters.json"),
        root.join("parameters.json"),
    )
    .expect("create external sidecar symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&external);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn external_parent_template_manifest_symlink_is_ignored() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-parent-manifest-root-{}-{unique}",
        std::process::id()
    ));
    let external = std::env::temp_dir().join(format!(
        "logicapps-lint-parent-manifest-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("default");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::fs::create_dir_all(&external).expect("create external manifest dir");
    std::fs::write(
        workflow_dir.join("workflow.json"),
        r#"{
  "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "$connections": {
      "type": "Object"
    }
  },
  "triggers": {
    "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
  },
  "actions": {
    "Call": {
      "type": "Compose",
      "inputs": "@parameters('$connections')['conn_#workflowname#']['connectionId']",
      "runAfter": {}
    }
  },
  "outputs": {}
}"#,
    )
    .expect("write workflow");
    std::fs::write(
        workflow_dir.join("manifest.json"),
        r#"{
  "id": "default",
  "title": "Fixture template",
  "summary": "Fixture template.",
  "description": "Fixture template.",
  "artifacts": [
    {
      "type": "workflow",
      "file": "workflow.json"
    }
  ],
  "images": {
    "light": "workflow-light",
    "dark": "workflow-dark"
  },
  "parameters": [],
  "connections": {
    "conn_#workflowname#": {
      "connectorId": "/serviceProviders/serviceBus",
      "kind": "inapp"
    }
  }
}"#,
    )
    .expect("write local manifest");
    std::fs::write(
        external.join("manifest.json"),
        r#"{
  "id": "pkg",
  "title": "External",
  "summary": "External package",
  "skus": [
    "consumption"
  ],
  "workflows": {
    "default": {
      "name": "Default"
    }
  },
  "featuredConnectors": [],
  "details": {
    "By": "Microsoft",
    "Type": "Workflow"
  }
}"#,
    )
    .expect("write external manifest");
    std::os::unix::fs::symlink(external.join("manifest.json"), root.join("manifest.json"))
        .expect("create external parent manifest symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&workflow_dir)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&external);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"code\": \"template-workflow-invalid-connections-parameter\""));
}

#[cfg(unix)]
#[test]
fn unreadable_external_sidecar_symlink_does_not_fail_directory_scan() {
    use std::os::unix::fs::PermissionsExt;

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-unreadable-sidecar-root-{}-{unique}",
        std::process::id()
    ));
    let external = std::env::temp_dir().join(format!(
        "logicapps-lint-unreadable-sidecar-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("Main");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::fs::create_dir_all(&external).expect("create external sidecar dir");
    std::fs::write(root.join("host.json"), r#"{ "version": "2.0" }"#).expect("write host");
    std::fs::write(workflow_dir.join("workflow.json"), CLEAN_WORKFLOW).expect("write workflow");
    std::fs::write(
        external.join("parameters.json"),
        r#"{ "queueName": { "value": "outside" } }"#,
    )
    .expect("write external sidecar");
    std::os::unix::fs::symlink(
        external.join("parameters.json"),
        root.join("parameters.json"),
    )
    .expect("create external sidecar symlink");
    let original_permissions = std::fs::metadata(&external)
        .expect("external metadata")
        .permissions();
    std::fs::set_permissions(&external, std::fs::Permissions::from_mode(0o0))
        .expect("make external sidecar dir unreadable");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::set_permissions(&external, original_permissions);
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&external);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn symlinked_input_root_keeps_internal_sidecar_symlink() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let parent = std::env::temp_dir().join(format!(
        "logicapps-lint-rootlink-sidecar-{}-{unique}",
        std::process::id()
    ));
    let real = parent.join("real");
    let link = parent.join("link");
    let workflow_dir = real.join("Main");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::os::unix::fs::symlink(&real, &link).expect("create input root symlink");
    std::fs::write(real.join("host.json"), r#"{ "version": "2.0" }"#).expect("write host");
    std::fs::write(
        workflow_dir.join("workflow.json"),
        r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
      "alertThreshold": {
        "type": "String"
      }
    },
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {}
  },
  "kind": "Stateful"
}"#,
    )
    .expect("write workflow");
    std::fs::write(
        real.join("params.actual.json"),
        r#"{ "alertThreshold": { "type": "String", "value": "10" } }"#,
    )
    .expect("write parameters target");
    std::os::unix::fs::symlink("params.actual.json", real.join("parameters.json"))
        .expect("create internal sidecar symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&link)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&parent);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn symlinked_input_root_keeps_internal_parent_manifest_symlink() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let parent = std::env::temp_dir().join(format!(
        "logicapps-lint-rootlink-manifest-{}-{unique}",
        std::process::id()
    ));
    let real = parent.join("real");
    let link = parent.join("link");
    let workflow_dir = real.join("default");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::os::unix::fs::symlink(&real, &link).expect("create input root symlink");
    std::fs::write(
        workflow_dir.join("workflow.json"),
        r#"{
  "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "$connections": {
      "type": "Object"
    }
  },
  "triggers": {
    "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
  },
  "actions": {
    "Call": {
      "type": "Compose",
      "inputs": "@parameters('$connections')['conn_#workflowname#']['connectionId']",
      "runAfter": {}
    }
  },
  "outputs": {}
}"#,
    )
    .expect("write workflow");
    std::fs::write(
        workflow_dir.join("manifest.json"),
        r#"{
  "id": "default",
  "title": "Fixture template",
  "summary": "Fixture template.",
  "description": "Fixture template.",
  "artifacts": [
    {
      "type": "workflow",
      "file": "workflow.json"
    }
  ],
  "images": {
    "light": "workflow-light",
    "dark": "workflow-dark"
  },
  "parameters": [],
  "connections": {
    "conn_#workflowname#": {
      "connectorId": "/serviceProviders/serviceBus",
      "kind": "inapp"
    }
  }
}"#,
    )
    .expect("write local manifest");
    std::fs::write(workflow_dir.join("workflow-light.png"), "placeholder")
        .expect("write light image");
    std::fs::write(workflow_dir.join("workflow-dark.png"), "placeholder")
        .expect("write dark image");
    std::fs::write(
        real.join("manifest.actual.json"),
        r#"{
  "id": "real",
  "title": "Fixture template",
  "summary": "Fixture template.",
  "skus": [
    "consumption"
  ],
  "workflows": {
    "default": {
      "name": "Default"
    }
  },
  "featuredConnectors": [],
  "details": {
    "By": "Microsoft",
    "Type": "Workflow"
  }
}"#,
    )
    .expect("write manifest target");
    std::os::unix::fs::symlink("manifest.actual.json", real.join("manifest.json"))
        .expect("create internal parent manifest symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(link.join("default"))
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&parent);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn external_fifo_sidecar_symlink_does_not_block_direct_workflow_input() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-fifo-sidecar-root-{}-{unique}",
        std::process::id()
    ));
    let external = std::env::temp_dir().join(format!(
        "logicapps-lint-fifo-sidecar-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("Main");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::fs::create_dir_all(&external).expect("create external sidecar dir");
    std::fs::write(workflow_dir.join("workflow.json"), CLEAN_WORKFLOW).expect("write workflow");
    let fifo = external.join("parameters.json");
    let mkfifo_status = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("run mkfifo");
    assert!(mkfifo_status.success(), "mkfifo must succeed");
    std::os::unix::fs::symlink(&fifo, root.join("parameters.json"))
        .expect("create external fifo sidecar symlink");

    let mut child = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(workflow_dir.join("workflow.json"))
        .arg("--format")
        .arg("json")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn logicapps-lint");
    let mut exited = false;
    for _ in 0..40 {
        if child.try_wait().expect("poll child").is_some() {
            exited = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&external);
        panic!("logicapps-lint hung while probing external FIFO sidecar");
    };
    let output = child.wait_with_output().expect("collect output");

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&external);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn in_root_fifo_sidecar_does_not_block_directory_scan() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-in-root-fifo-sidecar-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("Main");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::fs::write(root.join("host.json"), "{}").expect("write host");
    std::fs::write(workflow_dir.join("workflow.json"), CLEAN_WORKFLOW).expect("write workflow");
    let mkfifo_status = Command::new("mkfifo")
        .arg(root.join("parameters.json"))
        .status()
        .expect("run mkfifo");
    assert!(mkfifo_status.success(), "mkfifo must succeed");

    let mut child = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn logicapps-lint");
    let mut exited = false;
    for _ in 0..40 {
        if child.try_wait().expect("poll child").is_some() {
            exited = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&root);
        panic!("logicapps-lint hung while probing in-root FIFO sidecar");
    };
    let output = child.wait_with_output().expect("collect output");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn unreadable_external_workflow_symlink_does_not_fail_directory_scan() {
    use std::os::unix::fs::PermissionsExt;

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-unreadable-workflow-root-{}-{unique}",
        std::process::id()
    ));
    let external = std::env::temp_dir().join(format!(
        "logicapps-lint-unreadable-workflow-{}-{unique}",
        std::process::id()
    ));
    let good_dir = root.join("Good");
    let linked_dir = root.join("Linked");
    std::fs::create_dir_all(&good_dir).expect("create good workflow dir");
    std::fs::create_dir_all(&linked_dir).expect("create linked workflow dir");
    std::fs::create_dir_all(&external).expect("create external dir");
    std::fs::write(good_dir.join("workflow.json"), CLEAN_WORKFLOW).expect("write workflow");
    std::fs::write(external.join("workflow.json"), r#"{ "bad": true }"#)
        .expect("write external workflow");
    std::os::unix::fs::symlink(
        external.join("workflow.json"),
        linked_dir.join("workflow.json"),
    )
    .expect("create external workflow symlink");
    let original_permissions = std::fs::metadata(&external)
        .expect("external metadata")
        .permissions();
    std::fs::set_permissions(&external, std::fs::Permissions::from_mode(0o0))
        .expect("make external dir unreadable");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::set_permissions(&external, original_permissions);
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&external);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn unreadable_external_symlink_dir_sidecar_does_not_fail_directory_scan() {
    use std::os::unix::fs::PermissionsExt;

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-unreadable-dir-sidecar-root-{}-{unique}",
        std::process::id()
    ));
    let external = std::env::temp_dir().join(format!(
        "logicapps-lint-unreadable-dir-sidecar-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("Main");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::fs::create_dir_all(&external).expect("create external dir");
    std::fs::write(root.join("host.json"), r#"{ "version": "2.0" }"#).expect("write host");
    std::fs::write(workflow_dir.join("workflow.json"), CLEAN_WORKFLOW).expect("write workflow");
    std::fs::write(external.join("parameters.json"), "{}").expect("write external sidecar");
    std::os::unix::fs::symlink(&external, root.join("external-link"))
        .expect("create external dir symlink");
    std::os::unix::fs::symlink(
        "external-link/parameters.json",
        root.join("parameters.json"),
    )
    .expect("create chained sidecar symlink");
    let original_permissions = std::fs::metadata(&external)
        .expect("external metadata")
        .permissions();
    std::fs::set_permissions(&external, std::fs::Permissions::from_mode(0o0))
        .expect("make external dir unreadable");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::set_permissions(&external, original_permissions);
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&external);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn unreadable_in_root_directory_surfaces_walk_error() {
    use std::os::unix::fs::PermissionsExt;

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-unreadable-in-root-{}-{unique}",
        std::process::id()
    ));
    let private = root.join("private");
    std::fs::create_dir_all(&private).expect("create private dir");
    std::fs::write(private.join("workflow.json"), CLEAN_WORKFLOW).expect("write workflow");
    let original_permissions = std::fs::metadata(&private)
        .expect("private metadata")
        .permissions();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o0))
        .expect("make private dir unreadable");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::set_permissions(&private, original_permissions);
    let _ = std::fs::remove_dir_all(&root);
    // An in-root chmod-000 directory must surface as a walk error (exit 2),
    // never as `no-workflows-found` (exit 1) or a silent success.
    assert_eq!(output.status.code(), Some(2));
}

#[cfg(unix)]
#[test]
fn symlink_loop_does_not_fail_clean_directory_scan() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-symlink-loop-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("Main");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::fs::write(workflow_dir.join("workflow.json"), CLEAN_WORKFLOW).expect("write workflow");
    std::os::unix::fs::symlink("..", workflow_dir.join("loop")).expect("create symlink loop");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[cfg(unix)]
#[test]
fn direct_symlinked_workflow_keeps_project_context() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-symlink-project-{}-{unique}",
        std::process::id()
    ));
    let real_dir = root.join("Real");
    let link_dir = root.join("Main");
    std::fs::create_dir_all(&real_dir).expect("create real dir");
    std::fs::create_dir_all(&link_dir).expect("create link dir");
    std::fs::write(root.join("host.json"), "{}").expect("write host");
    std::fs::write(root.join("parameters.json"), r#"{ "parameters": {} }"#)
        .expect("write parameters");
    let real_workflow = real_dir.join("workflow.json");
    std::fs::write(
        &real_workflow,
        r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {},
    "parameters": {
      "Missing": {
        "type": "String"
      }
    }
  },
  "kind": "Stateful"
}"#,
    )
    .expect("write workflow");
    let symlinked_workflow = link_dir.join("workflow.json");
    std::os::unix::fs::symlink(&real_workflow, &symlinked_workflow)
        .expect("create workflow symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&symlinked_workflow)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"code\": \"project-missing-root-parameter\""));
    assert!(stdout.contains("\"path\": \"parameters.json\""));
}

#[test]
fn workflow_directory_uses_parent_project_files() {
    let fixture = fixture_path("project/root_parameters_clean/root_parameters_clean");
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[test]
fn workflow_directory_uses_parent_manifest() {
    let fixture = fixture_path("project/template-manifest-parent-clean/child");
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[test]
fn workflow_directory_reports_malformed_parent_manifest() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-parent-manifest-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("default");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::fs::write(root.join("manifest.json"), "{ broken json\n").expect("write parent manifest");
    std::fs::write(workflow_dir.join("workflow.json"), CLEAN_DIRECT_WORKFLOW)
        .expect("write workflow");
    std::fs::write(workflow_dir.join("workflow-light.png"), "placeholder").expect("write image");
    std::fs::write(workflow_dir.join("workflow-dark.png"), "placeholder").expect("write image");
    std::fs::write(
        workflow_dir.join("manifest.json"),
        r#"{
  "id": "default",
  "title": "Default Workflow",
  "summary": "Default workflow.",
  "description": "Default workflow.",
  "artifacts": [{ "type": "workflow", "file": "workflow.json" }],
  "images": { "light": "workflow-light", "dark": "workflow-dark" },
  "parameters": [],
  "connections": {}
}
"#,
    )
    .expect("write local manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&workflow_dir)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(1));
    let diagnostics: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("json diagnostics");
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0]["code"], "json-parse-error");
    assert_eq!(diagnostics[0]["path"], "../manifest.json");
}

#[test]
fn direct_workflow_parent_manifest_diagnostic_uses_relative_path() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-parent-manifest-file-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("default");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::fs::write(root.join("manifest.json"), "{ broken json\n").expect("write parent manifest");
    std::fs::write(workflow_dir.join("workflow.json"), CLEAN_DIRECT_WORKFLOW)
        .expect("write workflow");
    std::fs::write(workflow_dir.join("workflow-light.png"), "placeholder").expect("write image");
    std::fs::write(workflow_dir.join("workflow-dark.png"), "placeholder").expect("write image");
    std::fs::write(
        workflow_dir.join("manifest.json"),
        r#"{
  "id": "default",
  "title": "Default Workflow",
  "summary": "Default workflow.",
  "description": "Default workflow.",
  "artifacts": [{ "type": "workflow", "file": "workflow.json" }],
  "images": { "light": "workflow-light", "dark": "workflow-dark" },
  "parameters": [],
  "connections": {}
}
"#,
    )
    .expect("write local manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(workflow_dir.join("workflow.json"))
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"path\": \"../manifest.json\""));
    assert!(!stdout.contains("logicapps-lint-parent-manifest-file"));
}

#[test]
fn single_file_json_output_uses_file_name() {
    let fixture = fixture_path("references/unknown-action-refs/Main/workflow.json");
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"path\": \"workflow.json\""));
    assert!(!stdout.contains("\"path\": \"\""));
}

#[test]
fn single_non_workflow_json_is_an_error() {
    let fixture = fixture_path("parse/non-workflow-file/input.json");
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"code\": \"workflow-definition-not-found\""));
    assert!(stdout.contains("\"path\": \"input.json\""));
}

#[test]
fn json_output_includes_message_for_same_pointer_diagnostics() {
    let fixture = fixture_path("project/connections-multiple-missing-parameters");
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(1));
    let diagnostics: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("json diagnostics");
    let messages: Vec<_> = diagnostics
        .iter()
        .filter(|diagnostic| {
            diagnostic["code"] == "project-missing-connection-parameter"
                && diagnostic["pointer"] == "/managedApiConnections/blob/authentication"
        })
        .filter_map(|diagnostic| diagnostic["message"].as_str())
        .collect();

    assert_eq!(messages.len(), 2);
    assert!(messages.iter().any(|message| message.contains("missingA")));
    assert!(messages.iter().any(|message| message.contains("missingB")));
}

#[test]
fn tracked_properties_length_limit_is_reported() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("logicapps-lint-tracked-long-{unique}"));
    std::fs::create_dir_all(&root).expect("create fixture dir");
    let too_long = "x".repeat(8001);
    let workflow = format!(
        r#"{{
  "kind": "Stateful",
  "definition": {{
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {{
      "manual": {{ "type": "Request", "kind": "Http", "inputs": {{ "schema": {{}} }} }}
    }},
    "actions": {{
      "C": {{
        "type": "Compose",
        "inputs": "ok",
        "runAfter": {{}},
        "trackedProperties": {{ "tooLong": "{too_long}" }}
      }}
    }}
  }}
}}"#
    );
    std::fs::write(root.join("workflow.json"), workflow).expect("write workflow");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(1));
    let diagnostics: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("json diagnostics");
    assert_eq!(diagnostics[0]["code"], "workflow-shape-invalid-value");
    assert_eq!(
        diagnostics[0]["pointer"],
        "/definition/actions/C/trackedProperties"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn items_out_of_scope_message_does_not_say_missing() {
    let fixture = fixture_path("references/items-out-of-scope");
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(1));
    let diagnostics: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("json diagnostics");
    let message = diagnostics
        .iter()
        .find(|diagnostic| diagnostic["code"] == "unknown-foreach-reference")
        .and_then(|diagnostic| diagnostic["message"].as_str())
        .expect("unknown-foreach-reference message");

    assert!(message.contains("outside its actions scope"));
    assert!(!message.contains("missing Foreach"));
}

#[test]
fn parent_project_file_diagnostics_are_relative_to_common_base() {
    let fixture = fixture_path("project/root_parameters_missing/root_parameters_missing");
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"path\": \"parameters.json\""));
    assert!(!stdout.contains(env!("CARGO_MANIFEST_DIR")));
}

#[test]
fn direct_workflow_file_project_diagnostics_are_relative_to_project_base() {
    let fixture =
        fixture_path("project/root_parameters_missing/root_parameters_missing/workflow.json");
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&fixture)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"path\": \"parameters.json\""));
    assert!(!stdout.contains(env!("CARGO_MANIFEST_DIR")));
}

#[test]
fn workflow_diagnostic_paths_do_not_depend_on_project_diagnostics() {
    for case in [
        "project/stable-path-without-project-diagnostic/child",
        "project/stable-path-with-project-diagnostic/child",
    ] {
        let fixture = fixture_path(case);
        let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
            .arg(&fixture)
            .arg("--format")
            .arg("json")
            .output()
            .expect("run logicapps-lint");

        assert_eq!(output.status.code(), Some(1));
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(stdout.contains("\"path\": \"child/workflow.json\""));
        assert!(!stdout.contains("\"path\": \"workflow.json\""));
    }
}

#[test]
fn json_output_preserves_unix_backslash_path_components() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-backslash-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("a\\b").join("Main");
    std::fs::create_dir_all(&workflow_dir).expect("create fixture dir");
    std::fs::write(
        workflow_dir.join("workflow.json"),
        r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {},
    "actions": {
      "Bad": {
        "type": "Compose",
        "inputs": "@outputs('Missing')",
        "runAfter": {}
      }
    },
    "outputs": {}
  },
  "kind": "Stateful"
}
"#,
    )
    .expect("write workflow");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"path\": \"a\\\\b/Main/workflow.json\""));
    assert!(!stdout.contains("\"path\": \"a/b/Main/workflow.json\""));
}

#[test]
fn root_count_caps_are_reported() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-root-count-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("Main");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    let actions = (0..501)
        .map(|index| format!(r#""A{index}":{{"type":"Compose","inputs":"x","runAfter":{{}}}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let parameters = (0..51)
        .map(|index| format!(r#""P{index}":{{"type":"String"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let outputs = (0..11)
        .map(|index| format!(r#""O{index}":{{"type":"String"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    std::fs::write(
        workflow_dir.join("workflow.json"),
        format!(
            r#"{{
  "definition": {{
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {{}},
    "actions": {{{actions}}},
    "parameters": {{{parameters}}},
    "outputs": {{{outputs}}}
  }}
}}
"#
        ),
    )
    .expect("write workflow");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(1));
    let diagnostics: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("json diagnostics");
    for pointer in [
        "/definition/actions",
        "/definition/parameters",
        "/definition/outputs",
    ] {
        assert!(
            diagnostics.iter().any(|diagnostic| {
                diagnostic["code"] == "workflow-shape-invalid-value"
                    && diagnostic["pointer"] == pointer
            }),
            "missing count diagnostic for {pointer}"
        );
    }
}

#[test]
fn sidecar_directory_is_ignored_in_json_output() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-sidecar-directory-json-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("Main");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::fs::write(root.join("host.json"), "{}").expect("write host");
    std::fs::create_dir(root.join("connections.json")).expect("create sidecar directory");
    std::fs::write(
        workflow_dir.join("workflow.json"),
        r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
      "NeedsValue": {
        "type": "String"
      }
    },
    "triggers": {},
    "actions": {
      "Use_Value": {
        "type": "Compose",
        "inputs": "@parameters('NeedsValue')",
        "runAfter": {}
      }
    },
    "outputs": {}
  },
  "kind": "Stateful"
}
"#,
    )
    .expect("write workflow");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"code\": \"project-missing-root-parameter\""));
    assert!(stdout.contains("\"path\": \"Main/workflow.json\""));
    assert!(!stdout.contains("\"code\": \"tool-error\""));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(!stderr.contains(&root.to_string_lossy().to_string()));
    assert!(!stdout.contains(&root.to_string_lossy().to_string()));
}

#[test]
fn sidecar_directory_is_ignored_in_human_output() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-sidecar-directory-human-{}-{unique}",
        std::process::id()
    ));
    let workflow_dir = root.join("Main");
    std::fs::create_dir_all(&workflow_dir).expect("create workflow dir");
    std::fs::write(root.join("host.json"), "{}").expect("write host");
    std::fs::create_dir(root.join("parameters.json")).expect("create sidecar directory");
    std::fs::write(
        workflow_dir.join("workflow.json"),
        r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
      "NeedsValue": {
        "type": "String"
      }
    },
    "triggers": {},
    "actions": {},
    "outputs": {}
  },
  "kind": "Stateful"
}
"#,
    )
    .expect("write workflow");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("project parameter files do not define a value for 'NeedsValue'"));
    assert!(!stdout.contains("failed to read JSON input"));
    assert!(!stdout.contains(&root.to_string_lossy().to_string()));
}

#[test]
fn human_output_uses_rust_style_source_annotations() {
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(fixture_path(
            "parse/schema-value-invalid/Main/workflow.json",
        ))
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("error[workflow-shape-invalid-value]:"));
    assert!(stdout.contains("--> workflow.json:"));
    assert!(stdout.contains('^'));
    assert!(stdout.contains("= note: JSON pointer:"));
    assert!(!stdout.contains("\u{1b}["));
}

#[test]
fn direct_workflow_reads_parent_template_manifest_context() {
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(fixture_path(
            "project/template-consumption-parent-skus-clean/default/workflow.json",
        ))
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[test]
fn default_directory_reads_parent_template_manifest_context() {
    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(fixture_path(
            "project/template-consumption-parent-skus-clean/default",
        ))
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");
}

#[test]
fn total_action_limit_counts_nested_actions() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-action-count-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create fixture dir");

    let mut nested_actions = String::new();
    for index in 0..500 {
        if index > 0 {
            nested_actions.push(',');
        }
        write!(
            nested_actions,
            r#""A{index}":{{"type":"Compose","inputs":"ok","runAfter":{{}}}}"#
        )
        .expect("write action");
    }
    let workflow = format!(
        r#"{{
  "definition": {{
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {{}},
    "actions": {{
      "Group": {{
        "type": "Scope",
        "actions": {{{nested_actions}}},
        "runAfter": {{}}
      }}
    }},
    "outputs": {{}}
  }},
  "kind": "Stateful"
}}
"#
    );
    std::fs::write(root.join("workflow.json"), workflow).expect("write workflow");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"code\": \"workflow-shape-invalid-value\""));
    assert!(stdout.contains("\"pointer\": \"/definition/actions\""));
}

#[test]
fn action_nesting_depth_limit_is_enforced() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "logicapps-lint-action-depth-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create fixture dir");

    let mut action = String::from(r#""Scope9":{"type":"Scope","actions":{},"runAfter":{}}"#);
    for depth in (1..9).rev() {
        action =
            format!(r#""Scope{depth}":{{"type":"Scope","actions":{{{action}}},"runAfter":{{}}}}"#);
    }
    let workflow = format!(
        r#"{{
  "definition": {{
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {{}},
    "actions": {{{action}}},
    "outputs": {{}}
  }},
  "kind": "Stateful"
}}
"#
    );
    std::fs::write(root.join("workflow.json"), workflow).expect("write workflow");

    let output = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"))
        .arg(&root)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run logicapps-lint");

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"code\": \"workflow-shape-invalid-value\""));
    assert!(stdout.contains("Scope9"));
}

fn fixture_path(relative: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative)
}

const CLEAN_WORKFLOW: &str = r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {}
  },
  "kind": "Stateful"
}
"#;

const CLEAN_DIRECT_WORKFLOW: &str = r#"{
  "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
  "contentVersion": "1.0.0.0",
  "triggers": {
    "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
  },
  "actions": {},
  "outputs": {}
}
"#;

/// Materialize a workflow.json in a fresh temporary directory and return the
/// directory path. The directory is left on disk for the caller to remove
/// after the test completes.
fn write_temp_workflow(label: &str, body: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let fixture = std::env::temp_dir().join(format!(
        "logicapps-lint-{label}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&fixture).expect("create fixture dir");
    std::fs::write(fixture.join("workflow.json"), body).expect("write workflow.json");
    fixture
}

fn run_lint(fixture: &std::path::Path, extra_args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_logicapps-lint"));
    command.arg(fixture).arg("--format").arg("json");
    for arg in extra_args {
        command.arg(arg);
    }
    command.output().expect("run logicapps-lint")
}

fn json_codes(output: &std::process::Output) -> Vec<(String, String)> {
    let stdout = String::from_utf8(output.stdout.clone()).expect("utf8 stdout");
    let diagnostics: Vec<serde_json::Value> =
        serde_json::from_str(&stdout).expect("json diagnostics");
    diagnostics
        .into_iter()
        .map(|diagnostic| {
            (
                diagnostic["code"].as_str().unwrap().to_owned(),
                diagnostic["severity"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// The workflow declares `runAfter` with the uppercase `SUCCEEDED` variant
/// that Microsoft's own templates commonly ship. The runtime accepts it, so
/// the default (lenient) run must exit clean while `--strict` still enforces
/// the documented PascalCase spelling.
#[test]
fn uppercase_runafter_status_is_clean_by_default_but_error_under_strict() {
    let body = r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {
      "First":  { "type": "Compose", "inputs": {}, "runAfter": {} },
      "Second": { "type": "Compose", "inputs": {}, "runAfter": { "First": ["SUCCEEDED"] } }
    }
  },
  "kind": "Stateful"
}
"#;
    let fixture = write_temp_workflow("uppercase-runafter", body);

    let lenient = run_lint(&fixture, &[]);
    assert_eq!(lenient.status.code(), Some(0));
    assert!(json_codes(&lenient).is_empty());

    let strict = run_lint(&fixture, &["--strict"]);
    assert_eq!(strict.status.code(), Some(1));
    let codes = json_codes(&strict);
    assert!(
        codes
            .iter()
            .any(|(code, severity)| code == "runafter-invalid-status" && severity == "error"),
        "expected runafter-invalid-status error under --strict, got {codes:?}",
    );

    let _ = std::fs::remove_dir_all(&fixture);
}

/// A runAfter status that is not a known variant of any documented literal
/// must remain an error even in lenient mode — the case-insensitive relax
/// covers case only, not arbitrary strings.
#[test]
fn unknown_runafter_status_is_error_even_under_lenient() {
    let body = r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {
      "First":  { "type": "Compose", "inputs": {}, "runAfter": {} },
      "Second": { "type": "Compose", "inputs": {}, "runAfter": { "First": ["DONE"] } }
    }
  },
  "kind": "Stateful"
}
"#;
    let fixture = write_temp_workflow("unknown-runafter", body);

    let output = run_lint(&fixture, &[]);
    assert_eq!(output.status.code(), Some(1));
    let codes = json_codes(&output);
    assert!(
        codes
            .iter()
            .any(|(code, severity)| code == "runafter-invalid-status" && severity == "error"),
        "expected runafter-invalid-status error, got {codes:?}",
    );

    let _ = std::fs::remove_dir_all(&fixture);
}

/// An unknown action `type` is treated as a registry gap in lenient mode
/// (warning, exit 0) and elevated to an error under `--strict`.
#[test]
fn unknown_action_type_is_warning_by_default_but_error_under_strict() {
    let body = r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {
      "MyStep": { "type": "ChunkText", "inputs": {}, "runAfter": {} }
    }
  },
  "kind": "Stateful"
}
"#;
    let fixture = write_temp_workflow("unknown-action-type", body);

    let lenient = run_lint(&fixture, &[]);
    assert_eq!(lenient.status.code(), Some(0));
    let codes = json_codes(&lenient);
    assert!(
        codes
            .iter()
            .any(|(code, severity)| code == "workflow-shape-unknown-type" && severity == "warning"),
        "expected workflow-shape-unknown-type warning under lenient, got {codes:?}",
    );

    let strict = run_lint(&fixture, &["--strict"]);
    assert_eq!(strict.status.code(), Some(1));
    let codes = json_codes(&strict);
    assert!(
        codes
            .iter()
            .any(|(code, severity)| code == "workflow-shape-unknown-type" && severity == "error"),
        "expected workflow-shape-unknown-type error under --strict, got {codes:?}",
    );

    let _ = std::fs::remove_dir_all(&fixture);
}

/// A definition parameter typed with a lowercase primitive (`string`, `int`,
/// `bool`) is a runtime-tolerated case variant of the documented schema and
/// must clear the default run; `--strict` still flags it as invalid-value.
#[test]
fn lowercase_parameter_type_is_clean_by_default_but_error_under_strict() {
    let body = r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
      "count": { "type": "int", "defaultValue": 3 }
    },
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {}
  },
  "kind": "Stateful"
}
"#;
    let fixture = write_temp_workflow("lowercase-param-type", body);

    let lenient = run_lint(&fixture, &[]);
    assert_eq!(lenient.status.code(), Some(0));
    let codes = json_codes(&lenient);
    assert!(
        !codes
            .iter()
            .any(|(code, _)| code == "workflow-shape-invalid-value"),
        "parameter-type invalid-value should not appear under lenient, got {codes:?}",
    );

    let strict = run_lint(&fixture, &["--strict"]);
    assert_eq!(strict.status.code(), Some(1));
    let codes = json_codes(&strict);
    assert!(
        codes
            .iter()
            .any(|(code, severity)| code == "workflow-shape-invalid-value" && severity == "error"),
        "expected parameter-type invalid-value under --strict, got {codes:?}",
    );

    let _ = std::fs::remove_dir_all(&fixture);
}

/// A `Wait` action whose `interval.count` is a WDL expression must clear
/// the shape check — the runtime resolves the expression when the action
/// fires, so an author-time literal integer is not required.
#[test]
fn wait_interval_count_accepts_wdl_expression() {
    let body = r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
      "delayInSeconds": { "type": "Int", "defaultValue": 5 }
    },
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {
      "Pause": {
        "type": "Wait",
        "inputs": {
          "interval": { "count": "@parameters('delayInSeconds')", "unit": "Second" }
        },
        "runAfter": {}
      }
    }
  },
  "kind": "Stateful"
}
"#;
    let fixture = write_temp_workflow("wait-wdl-count", body);

    // Under --strict the expression must still pass — this is a plain bug fix,
    // not a lenient-only relaxation.
    let output = run_lint(&fixture, &["--strict"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(json_codes(&output).is_empty());

    let _ = std::fs::remove_dir_all(&fixture);
}

/// `--allow` still trumps `--strict` — a suppressed code drops entirely
/// regardless of the strictness mode.
#[test]
fn allow_suppresses_diagnostic_even_under_strict() {
    let body = r#"{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "manual": { "type": "Request", "kind": "Http", "inputs": { "schema": {} } }
    },
    "actions": {
      "MyStep": { "type": "ChunkText", "inputs": {}, "runAfter": {} }
    }
  },
  "kind": "Stateful"
}
"#;
    let fixture = write_temp_workflow("allow-with-strict", body);

    let output = run_lint(
        &fixture,
        &["--strict", "--allow", "workflow-shape-unknown-type"],
    );
    assert_eq!(output.status.code(), Some(0));
    let codes = json_codes(&output);
    assert!(
        !codes
            .iter()
            .any(|(code, _)| code == "workflow-shape-unknown-type"),
        "allow should have suppressed the code, got {codes:?}",
    );

    let _ = std::fs::remove_dir_all(&fixture);
}
