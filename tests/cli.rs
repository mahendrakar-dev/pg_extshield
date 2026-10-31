use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Stdio};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

struct TestFolder {
    path: PathBuf,
}

impl TestFolder {
    fn new() -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("pg-extshield-cli-{}-{id}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn write(&self, name: &str, content: impl AsRef<[u8]>) {
        std::fs::write(self.path.join(name), content).unwrap();
    }

    fn scan(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_pg_extshield"))
            .arg("scan")
            .arg(&self.path)
            .output()
            .unwrap()
    }
}

impl Drop for TestFolder {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).expect("remove this test's temporary folder");
    }
}

#[test]
fn reports_findings_with_details_locations_and_suggestions() {
    let folder = TestFolder::new();
    folder.write("demo.control", "# demo\ntrusted = true\n");
    folder.write("demo--1.0.sql", "");

    let output = folder.scan();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("[Low] CTL-001: Review schema safety"));
    assert!(stdout.contains("[Low] CTL-003:"));
    assert!(stdout.contains(&format!("{}:2", folder.path.join("demo.control").display())));
    assert!(stdout.contains("Details:"));
    assert!(stdout.contains("Suggestion:"));
    assert!(stdout.contains("Reference: https://www.postgresql.org/"));
    assert!(stdout.contains("Scanned 1 control file(s); 2 finding(s)."));
}

#[test]
fn checks_primary_files_in_order_and_skips_unsupported_inputs() {
    let folder = TestFolder::new();
    folder.write("z.control", "default_version = '1.0'\n");
    folder.write("a.control", "default_version = '1.0'\n");
    folder.write("a--1.1.control", "comment = 'override'\n");
    folder.write("a--1.0.sql", "");
    folder.write("z--1.0.sql", "");
    folder.write("orphan--1.control", "comment = 'orphan'");
    folder.write("notes.txt", "not a control file");
    let subfolder = folder.path.join("ignored.control");
    std::fs::create_dir(&subfolder).unwrap();
    std::fs::write(subfolder.join("nested.control"), "bad input").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("missing-target", folder.path.join("link.control")).unwrap();

    let output = folder.scan();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let checked: Vec<_> = stdout
        .lines()
        .filter(|line| line.starts_with("Checked control file:"))
        .collect();
    assert_eq!(checked.len(), 3);
    assert!(checked[0].ends_with("a--1.1.control"));
    assert!(checked[1].ends_with("a.control"));
    assert!(checked[2].ends_with("z.control"));
    assert!(stdout.contains("Skipped file:"));
    assert!(
        stdout.contains("No findings from the current control-file and script-filename checks.")
    );
    assert!(stdout.contains("Scanned 3 control file(s); 0 finding(s)."));
    assert!(!stdout.contains("CTL-003"));
}

#[test]
fn empty_folder_and_override_only_folder_do_not_claim_a_clean_scan() {
    let folder = TestFolder::new();
    for overrides_only in [false, true] {
        if overrides_only {
            folder.write("demo--1.0.control", "comment = 'override'");
        }
        let output = folder.scan();
        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("No primary .control files found"));
        assert!(stdout.contains("No checks were run."));
        assert!(!stdout.contains("No findings"));
        assert!(!stdout.contains("Scanned "));
    }
}

#[test]
fn parse_error_has_file_and_line_and_fails_the_command() {
    let folder = TestFolder::new();
    folder.write("demo.control", "# demo\ntrusted = maybe\n");

    let output = folder.scan();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Error: "));
    assert!(stderr.contains(&format!(
        "{}:2:",
        folder.path.join("demo.control").display()
    )));
    assert!(stderr.contains("invalid boolean for `trusted`"));
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("Scanned ")
    );
}

#[test]
fn unreadable_text_reports_its_path_and_fails_the_command() {
    let folder = TestFolder::new();
    folder.write("demo.control", [0xff]);

    let output = folder.scan();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("cannot read"));
    assert!(stderr.contains(&folder.path.join("demo.control").display().to_string()));
}

#[test]
fn rejects_missing_folders_and_file_paths() {
    let folder = TestFolder::new();
    folder.write("notes.txt", "not a folder");
    for name in ["missing", "notes.txt"] {
        let path = folder.path.join(name);
        let output = Command::new(env!("CARGO_BIN_EXE_pg_extshield"))
            .arg("scan")
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("cannot open folder"));
        assert!(stderr.contains(&path.display().to_string()));
    }
}

#[test]
fn help_documents_limits_and_missing_arguments_are_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_pg_extshield"))
        .args(["scan", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Version-specific"));
    assert!(stdout.contains("Exit codes:"));
    assert!(stdout.contains("No findings does not mean"));

    let output = Command::new(env!("CARGO_BIN_EXE_pg_extshield"))
        .arg("scan")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn failed_scan_does_not_print_a_partial_report() {
    let folder = TestFolder::new();
    folder.write("a.control", "trusted = true");
    folder.write("z.control", "trusted = typo");
    let output = folder.scan();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("z.control:1:")
    );
}

#[test]
fn installation_paths_use_directed_updates_and_handle_cycles() {
    let folder = TestFolder::new();
    folder.write("demo.control", "default_version = 'release'");
    for name in [
        "demo--base.sql",
        "demo--base--beta.sql",
        "demo--beta--base.sql",
        "demo--beta--release.sql",
        "demo--isolated--other.sql",
        "demo--other--isolated.sql",
    ] {
        // SQL contents are deliberately not readable as UTF-8.
        folder.write(name, [0xff]);
    }
    let report = pg_extshield::scan_extension(&folder.path).unwrap();
    assert!(report.findings.is_empty());
    let extension = &report.extensions[0];
    assert_eq!(extension.scripts.len(), 6);
    let release = extension
        .versions
        .iter()
        .find(|v| v.version == "release")
        .unwrap();
    assert_eq!(
        release.installation_path,
        Some(vec!["base".into(), "beta".into(), "release".into()])
    );
    let isolated = extension
        .versions
        .iter()
        .find(|v| v.version == "isolated")
        .unwrap();
    assert_eq!(isolated.installation_path, None);

    folder.write("demo--base--release.sql", "");
    let report = pg_extshield::scan_extension(&folder.path).unwrap();
    let release = report.extensions[0]
        .versions
        .iter()
        .find(|v| v.version == "release")
        .unwrap();
    assert_eq!(
        release.installation_path,
        Some(vec!["base".into(), "release".into()])
    );

    folder.write("demo--release.sql", "");
    let report = pg_extshield::scan_extension(&folder.path).unwrap();
    let release = report.extensions[0]
        .versions
        .iter()
        .find(|v| v.version == "release")
        .unwrap();
    assert_eq!(release.installation_path, Some(vec!["release".into()]));
}

#[test]
fn unreachable_defaults_and_missing_install_scripts_are_distinct_from_invalid_defaults() {
    let folder = TestFolder::new();
    folder.write("demo.control", "# header\ndefault_version = '1.2'");
    for name in ["demo--1.0.sql", "demo--1.0--1.1.sql", "demo--1.2--1.1.sql"] {
        folder.write(name, "");
    }
    let report = pg_extshield::scan_extension(&folder.path).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule_id, "CTL-004");
    assert_eq!(report.findings[0].line, Some(2));
    assert_eq!(report.findings[0].version.as_deref(), Some("1.2"));
    let output = folder.scan();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("[Medium] CTL-004")
    );

    folder.write("demo.control", "default_version = 'bad--version'");
    let report = pg_extshield::scan_extension(&folder.path).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule_id, "CTL-003");
    assert_eq!(report.findings[0].severity, pg_extshield::Severity::Medium);

    std::fs::remove_file(folder.path.join("demo--1.0.sql")).unwrap();
    folder.write("demo.control", "");
    let report = pg_extshield::scan_extension(&folder.path).unwrap();
    assert_eq!(report.findings.len(), 2);
    assert_eq!(report.findings[0].rule_id, "CTL-003");
    assert_eq!(report.findings[0].severity, pg_extshield::Severity::Low);
    assert_eq!(report.findings[1].rule_id, "CTL-004");
    assert!(report.findings[1].details.contains("Update scripts alone"));
}

#[test]
fn update_cycles_without_an_installation_base_are_not_installable() {
    let folder = TestFolder::new();
    folder.write("demo.control", "default_version = 'beta'");
    folder.write("demo--alpha--beta.sql", "");
    folder.write("demo--beta--alpha.sql", "");
    let report = pg_extshield::scan_extension(&folder.path).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule_id, "CTL-004");
    assert!(
        report.extensions[0]
            .versions
            .iter()
            .all(|v| v.installation_path.is_none())
    );
}

#[test]
fn version_labels_are_case_sensitive_and_scripts_cannot_cross_extensions() {
    let folder = TestFolder::new();
    folder.write("demo.control", "default_version = 'Beta'");
    folder.write("demo--beta.sql", "");
    folder.write("other--Beta.sql", "");
    let report = pg_extshield::scan_extension(&folder.path).unwrap();
    assert_eq!(report.findings[0].rule_id, "CTL-004");
    assert_eq!(
        report.extensions[0].scripts,
        vec![folder.path.join("demo--beta.sql")]
    );
}

#[test]
fn malformed_filenames_are_reported_but_not_used_as_paths() {
    let folder = TestFolder::new();
    folder.write("demo.control", "default_version = '1'");
    folder.write("demo--1.sql", "");
    for name in [
        "demo--.sql",
        "demo---1.sql",
        "demo--1-.sql",
        "demo--1--2--3.sql",
        "demo--.control",
        "demo--1--2.control",
    ] {
        folder.write(name, "not read");
    }
    let report = pg_extshield::scan_extension(&folder.path).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.extensions[0].scripts.len(), 1);
    assert_eq!(report.extensions[0].versions.len(), 1);
    assert_eq!(report.skipped_files.len(), 6);
    assert!(
        report
            .skipped_files
            .iter()
            .all(|f| f.reason.contains("Invalid extension filename"))
    );
}

#[test]
fn relative_directories_use_an_explicit_installation_base_in_cli_and_library() {
    let folder = TestFolder::new();
    let base = TestFolder::new();
    std::fs::create_dir(base.path.join("scripts")).unwrap();
    std::fs::create_dir(folder.path.join("scripts")).unwrap();
    folder.write(
        "demo.control",
        "default_version = '1'\ndirectory = 'scripts'",
    );
    folder.write("scripts/demo--wrong.sql", "");
    folder.write(
        "demo--1.control",
        "invalid but outside the script directory",
    );
    base.write("scripts/demo--1.sql", "");
    base.write("scripts/demo--1.control", "# override\ntrusted = true");

    let error = pg_extshield::scan_extension(&folder.path).unwrap_err();
    assert!(error.to_string().contains("demo.control:2:"));
    assert!(error.to_string().contains("installation base"));
    let output = folder.scan();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("--installation-base")
    );

    let report = pg_extshield::scan_extension_with_base(&folder.path, Some(&base.path)).unwrap();
    assert_eq!(
        report.extensions[0].script_directory,
        base.path.join("scripts")
    );
    assert_eq!(
        report.extensions[0].scripts,
        vec![base.path.join("scripts/demo--1.sql")]
    );
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule_id, "CTL-001");
    assert_eq!(
        report.findings[0].file,
        base.path.join("scripts/demo--1.control")
    );
    assert_eq!(report.findings[0].line, Some(2));
    assert_eq!(report.findings[0].version.as_deref(), Some("1"));
    assert_eq!(report.skipped_files.len(), 1);
    assert!(report.skipped_files[0].reason.contains("outside"));

    let output = Command::new(env!("CARGO_BIN_EXE_pg_extshield"))
        .arg("scan")
        .arg(&folder.path)
        .arg("--installation-base")
        .arg(&base.path)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("candidate installation path 1"));
    assert!(stdout.contains("demo--1.control:2"));
    assert!(stdout.contains("Version: \"1\""));
}

#[test]
fn absolute_script_directories_need_no_installation_base() {
    let folder = TestFolder::new();
    let scripts = TestFolder::new();
    let directory = scripts
        .path
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('\'', "''");
    folder.write(
        "demo.control",
        format!("default_version = '1'\ndirectory = '{directory}'"),
    );
    scripts.write("demo--1.sql", "");
    scripts.write("demo--1.control", "comment = 'override'");
    let report = pg_extshield::scan_extension(&folder.path).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.extensions[0].script_directory, scripts.path);
    assert!(
        report
            .scanned_files
            .contains(&scripts.path.join("demo--1.control"))
    );
}

#[test]
fn missing_or_non_directory_script_locations_are_errors_not_missing_script_findings() {
    let folder = TestFolder::new();
    folder.write("not_a_directory", "");
    for directory in ["missing", "not_a_directory"] {
        folder.write(
            "demo.control",
            format!("default_version = '1'\ndirectory = '{directory}'"),
        );
        let error =
            pg_extshield::scan_extension_with_base(&folder.path, Some(&folder.path)).unwrap_err();
        assert!(error.to_string().contains(directory));
        assert!(!error.to_string().contains("CTL-004"));
    }
}

#[test]
fn effective_controls_are_audited_for_every_version_without_override_carryover() {
    let folder = TestFolder::new();
    folder.write("demo.control", "default_version = '3'\ntrusted = false");
    folder.write("demo--1.sql", "");
    folder.write("demo--1--2.sql", "");
    folder.write("demo--2--3.sql", "");
    folder.write("demo--2.control", "# override\ntrusted = true");
    folder.write(
        "demo--3.control",
        "comment = 'back to the primary baseline'",
    );
    let report = pg_extshield::scan_extension(&folder.path).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule_id, "CTL-001");
    assert_eq!(report.findings[0].version.as_deref(), Some("2"));
    assert_eq!(report.findings[0].file, folder.path.join("demo--2.control"));
    assert_eq!(report.findings[0].line, Some(2));
    assert_eq!(report.extensions[0].versions.len(), 3);

    folder.write("demo.control", "default_version = '3'\ntrusted = true");
    folder.write("demo--2.control", "superuser = false");
    folder.write("demo--3.control", "schema = 'app'");
    let report = pg_extshield::scan_extension(&folder.path).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].version.as_deref(), Some("1"));
    assert_eq!(report.findings[0].file, folder.path.join("demo.control"));
}

#[test]
fn invalid_secondary_settings_fail_without_partial_cli_output() {
    let folder = TestFolder::new();
    folder.write("demo.control", "default_version = '1'\nrelocatable = true");
    folder.write("demo--1.sql", "");
    for setting in [
        "default_version = '2'",
        "directory = 'elsewhere'",
        "schema = 'app'",
    ] {
        folder.write("demo--1.control", format!("# header\n{setting}"));
        let output = folder.scan();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("demo--1.control:2:")
        );
    }
}

#[cfg(unix)]
#[test]
fn matching_script_and_secondary_symlinks_are_unverified_not_missing() {
    for name in ["demo--1.sql", "demo--1.control"] {
        let folder = TestFolder::new();
        folder.write("demo.control", "default_version = '1'");
        std::os::unix::fs::symlink("missing-target", folder.path.join(name)).unwrap();
        let error = pg_extshield::scan_extension(&folder.path).unwrap_err();
        assert!(error.to_string().contains(name));
        assert!(error.to_string().contains("cannot verify"));
        assert!(error.to_string().contains("symbolic-link"));
    }
}

struct McpClient {
    child: Child,
    input: ChildStdin,
    output: Receiver<String>,
    reader: Option<JoinHandle<()>>,
}

impl McpClient {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pg_extshield"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, output) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line.expect("read MCP stdout")).is_err() {
                    break;
                }
            }
        });
        let mut client = Self {
            child,
            input,
            output,
            reader: Some(reader),
        };
        let response = client.request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "pg-extshield-tests", "version": "1.0"}
            }),
        );
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["serverInfo"]["name"], "pg-extshield");
        assert!(response["result"]["capabilities"]["tools"].is_object());
        client.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        client
    }

    fn send(&mut self, message: Value) {
        writeln!(self.input, "{message}").unwrap();
        self.input.flush().unwrap();
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let line = self
                .output
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("MCP response before timeout");
            let message: Value = serde_json::from_str(&line).unwrap_or_else(|error| {
                panic!("stdout must contain only MCP JSON: {line:?}: {error}")
            });
            if message["id"] == id {
                return message;
            }
            assert!(
                message["method"].is_string(),
                "unexpected MCP message: {message}"
            );
        }
    }

    fn scan(&mut self, path: &std::path::Path) -> Value {
        self.request(
            3,
            "tools/call",
            json!({
                "name": "scan_extension",
                "arguments": {"path": path}
            }),
        )
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        if self.child.try_wait().expect("check test server").is_none() {
            self.child.kill().expect("stop test server");
        }
        self.child.wait().expect("reap test server");
        self.reader.take().unwrap().join().expect("join MCP reader");
    }
}

#[test]
fn mcp_discovers_tools_and_returns_the_shared_scanner_report() {
    let folder = TestFolder::new();
    folder.write("z.control", "default_version = '1.0'");
    folder.write("a.control", "# demo\ntrusted = true");
    folder.write("a--1.1.control", "comment = 'override'");
    folder.write("a--1.1.sql", "");
    folder.write("z--1.0.sql", "");
    folder.write("orphan--1.control", "comment = 'orphan'");
    folder.write("notes.txt", "not a control file");
    let subfolder = folder.path.join("ignored.control");
    std::fs::create_dir(&subfolder).unwrap();
    std::fs::write(subfolder.join("nested.control"), "bad input").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("missing-target", folder.path.join("link.control")).unwrap();

    let mut client = McpClient::start();
    let tools = client.request(2, "tools/list", json!({}));
    let tools = tools["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|tool| tool["name"] == "server_status"));
    let scan = tools
        .iter()
        .find(|tool| tool["name"] == "scan_extension")
        .unwrap();
    assert_eq!(scan["inputSchema"]["properties"]["path"]["type"], "string");
    assert_eq!(scan["inputSchema"]["required"], json!(["path"]));
    assert!(
        scan["inputSchema"]["properties"]
            .get("installation_base")
            .is_some()
    );

    let response = client.request(
        4,
        "tools/call",
        json!({
            "name": "server_status", "arguments": {}
        }),
    );
    assert_eq!(
        response["result"]["content"][0]["text"],
        "pg_extshield MCP server is responding. No scan was performed."
    );

    let response = client.scan(&folder.path);
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(response["result"]["isError"], false);
    let report = &response["result"]["structuredContent"];
    let expected = pg_extshield::scan_extension(&folder.path).unwrap();
    assert_eq!(report, &serde_json::to_value(expected).unwrap());
    assert_eq!(report["scanned_files"].as_array().unwrap().len(), 3);
    assert!(
        report["skipped_files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["reason"]
                .as_str()
                .unwrap()
                .contains("Version-specific"))
    );
    assert_eq!(report["findings"][0]["rule_id"], "CTL-001");
    assert_eq!(report["findings"][0]["line"], 2);
    assert_eq!(report["findings"][1]["rule_id"], "CTL-003");
    assert_eq!(report["findings"][0]["version"], "1.1");
    assert_eq!(
        report["rules_checked"],
        json!(["CTL-001", "CTL-003", "CTL-004"])
    );
    assert_eq!(
        report["extensions"][0]["versions"][0]["installation_path"],
        json!(["1.1"])
    );
    let text_report: Value =
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(&text_report, report);
}

#[test]
fn mcp_distinguishes_no_input_files_from_no_findings() {
    let folder = TestFolder::new();
    let mut client = McpClient::start();
    let response = client.scan(&folder.path);
    assert_eq!(response["result"]["isError"], false);
    let report = &response["result"]["structuredContent"];
    assert_eq!(report["scanned_files"], json!([]));
    assert_eq!(report["findings"], json!([]));
    assert_eq!(report["rules_checked"], json!([]));
    assert!(
        report["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|note| note.as_str().unwrap().contains("No checks were run."))
    );

    folder.write("demo.control", "default_version = '1.0'");
    folder.write("demo--1.0.sql", "");
    let response = client.scan(&folder.path);
    let report = &response["result"]["structuredContent"];
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(report["scanned_files"].as_array().unwrap().len(), 1);
    assert_eq!(report["findings"], json!([]));
    assert_eq!(
        report["rules_checked"],
        json!(["CTL-001", "CTL-003", "CTL-004"])
    );
}

#[test]
fn mcp_accepts_installation_base_and_reports_paths_overrides_and_errors() {
    let folder = TestFolder::new();
    let base = TestFolder::new();
    std::fs::create_dir(base.path.join("scripts")).unwrap();
    folder.write(
        "demo.control",
        "default_version = '2'\ndirectory = 'scripts'",
    );
    base.write("scripts/demo--1.sql", "");
    base.write("scripts/demo--1--2.sql", "");
    base.write("scripts/demo--2.control", "# override\ntrusted = true");
    let mut client = McpClient::start();

    let response = client.scan(&folder.path);
    assert_eq!(response["result"]["isError"], true);
    assert!(response["result"].get("structuredContent").is_none());
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("installation base")
    );

    let arguments = json!({"path": folder.path, "installation_base": base.path});
    let response = client.request(
        6,
        "tools/call",
        json!({
            "name": "scan_extension", "arguments": arguments.clone(),
        }),
    );
    assert_eq!(response["result"]["isError"], false);
    let report = &response["result"]["structuredContent"];
    let expected = pg_extshield::scan_extension_with_base(&folder.path, Some(&base.path)).unwrap();
    assert_eq!(report, &serde_json::to_value(expected).unwrap());
    assert_eq!(
        report["extensions"][0]["versions"][1]["installation_path"],
        json!(["1", "2"])
    );
    assert_eq!(report["findings"][0]["version"], "2");
    assert_eq!(report["findings"][0]["line"], 2);
    assert_eq!(
        report["findings"][0]["file"],
        json!(base.path.join("scripts/demo--2.control"))
    );

    base.write("scripts/demo--2.control", "default_version = '3'");
    let response = client.request(
        7,
        "tools/call",
        json!({
            "name": "scan_extension", "arguments": arguments,
        }),
    );
    assert_eq!(response["result"]["isError"], true);
    assert!(response["result"].get("structuredContent").is_none());
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("demo--2.control:1:")
    );

    folder.write(
        "demo.control",
        "default_version = '1'\ndirectory = 'missing'",
    );
    let response = client.request(
        8,
        "tools/call",
        json!({
            "name": "scan_extension",
            "arguments": {"path": folder.path, "installation_base": base.path},
        }),
    );
    assert_eq!(response["result"]["isError"], true);
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("cannot resolve script directory")
    );
}

#[test]
fn mcp_marks_scan_failures_as_tool_errors_and_keeps_serving() {
    let folder = TestFolder::new();
    folder.write("demo.control", "# demo\ntrusted = maybe");
    let mut client = McpClient::start();
    for (path, message) in [
        (folder.path.join("missing"), "cannot open folder"),
        (folder.path.join("demo.control"), "cannot open folder"),
        (folder.path.clone(), "demo.control:2: invalid boolean"),
    ] {
        let response = client.scan(&path);
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["isError"], true, "{response}");
        assert!(response["result"].get("structuredContent").is_none());
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(message), "{text}");
        assert!(text.contains("No complete report was produced."));
    }
    folder.write("demo.control", [0xff]);
    let response = client.scan(&folder.path);
    assert_eq!(response["result"]["isError"], true);
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("cannot read")
    );

    folder.write("demo.control", "default_version = '1.0'");
    assert_eq!(client.scan(&folder.path)["result"]["isError"], false);
}

#[test]
fn mcp_rejects_missing_wrong_and_extra_arguments() {
    let mut client = McpClient::start();
    for arguments in [
        json!({}),
        json!({"path": 123}),
        json!({"path": ".", "extra": true}),
        json!({"path": ".", "installation_base": 42}),
    ] {
        let response = client.request(
            5,
            "tools/call",
            json!({
                "name": "scan_extension", "arguments": arguments
            }),
        );
        assert_eq!(response["result"]["isError"], true, "{response}");
        assert!(
            response["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("failed to deserialize parameters"),
            "{response}"
        );
    }
}
