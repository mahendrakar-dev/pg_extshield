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

    let output = folder.scan();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("[Low] CTL-001: Review schema safety"));
    assert!(stdout.contains("[Medium] CTL-003:"));
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
    assert_eq!(checked.len(), 2);
    assert!(checked[0].ends_with("a.control"));
    assert!(checked[1].ends_with("z.control"));
    assert!(stdout.contains("Skipped version-specific control file:"));
    assert!(stdout.contains("No findings from the current control-file checks."));
    assert!(stdout.contains("Scanned 2 control file(s); 0 finding(s)."));
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
    assert_eq!(report["scanned_files"].as_array().unwrap().len(), 2);
    assert_eq!(report["skipped_files"].as_array().unwrap().len(), 1);
    assert!(
        report["skipped_files"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("Version-specific")
    );
    assert_eq!(report["findings"][0]["rule_id"], "CTL-001");
    assert_eq!(report["findings"][0]["line"], 2);
    assert_eq!(report["findings"][1]["rule_id"], "CTL-003");
    assert_eq!(report["rules_checked"], json!(["CTL-001", "CTL-003"]));
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
    let response = client.scan(&folder.path);
    let report = &response["result"]["structuredContent"];
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(report["scanned_files"].as_array().unwrap().len(), 1);
    assert_eq!(report["findings"], json!([]));
    assert_eq!(report["rules_checked"], json!(["CTL-001", "CTL-003"]));
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
