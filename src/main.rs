//! The CLI prints reports. MCP returns the same reports as data.

use rmcp::{
    ErrorData, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};

use serde::Deserialize;

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pg_extshield::{Finding, scan_extension};

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ScanRequest {
    /// Folder on the server's machine. Use an absolute path to avoid ambiguity.
    path: PathBuf,
}

struct PostgresExtShieldServer {
    tool_router: ToolRouter<Self>,
}
#[tool_router]
impl PostgresExtShieldServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Check that the pg_extshield MCP server responds. Does not scan files.")]
    async fn server_status(&self) -> String {
        "pg_extshield MCP server is responding. No scan was performed.".to_owned()
    }

    #[tool(
        description = "Read primary .control files directly inside an extension folder and run CTL-001 and CTL-003. Returns checked files, skipped version-specific files, findings, and limits. Does not execute extension code or inspect SQL, source, or binaries. No findings is not proof of safety."
    )]
    async fn scan_extension(
        &self,
        request: Parameters<ScanRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let path = request.0.path;
        // File reading is blocking work, so keep it off the async worker threads.
        let result = tokio::task::spawn_blocking(move || scan_extension(&path))
            .await
            .map_err(|error| {
                ErrorData::internal_error(format!("scan worker failed: {error}"), None)
            })?;
        match result {
            Ok(report) => {
                let value = serde_json::to_value(report).map_err(|error| {
                    ErrorData::internal_error(format!("cannot encode scan report: {error}"), None)
                })?;
                Ok(CallToolResult::structured(value))
            }
            Err(error) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "Scan failed: {error}. No complete report was produced."
            ))])),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for PostgresExtShieldServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new("pg-extshield", env!("CARGO_PKG_VERSION")),
        )
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Check primary .control files directly inside a folder.
    #[command(after_long_help = "\
Subfolders, symbolic links, SQL, source code, and compiled libraries are not checked.
Version-specific files such as demo--1.0.control are skipped: they need to be
combined with the primary control file before checking.

Exit codes: 0 = command completed, even with findings or no matching files;
1 = scan error; 2 = invalid command-line arguments.
The scan stops at the first error. No partial report is printed.
No findings does not mean an extension is safe.")]
    Scan { path: PathBuf },

    /// Start the MCP server over stdin and stdout.
    Mcp,
}

#[derive(Parser)]
#[command(author, version, about = "Check PostgreSQL extension files")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

async fn run_mcp() -> Result<(), Box<dyn Error>> {
    let server = PostgresExtShieldServer::new().serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Scan { path } => scan(&path),
        Commands::Mcp => run_mcp().await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}
fn scan(folder: &Path) -> Result<(), Box<dyn Error>> {
    let report = scan_extension(folder)?;
    for skipped in &report.skipped_files {
        println!(
            "Skipped version-specific control file: {}",
            skipped.path.display()
        );
    }
    for path in &report.scanned_files {
        let findings: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| &finding.file == path)
            .collect();
        println!("Checked control file: {}", path.display());
        if findings.is_empty() {
            println!("  No findings from the current control-file checks.");
        } else {
            for finding in findings {
                print_finding(finding);
            }
        }
    }

    if report.scanned_files.is_empty() {
        println!(
            "No primary .control files found in {}. No checks were run.",
            folder.display()
        );
    } else {
        println!(
            "Scanned {} control file(s); {} finding(s).",
            report.scanned_files.len(),
            report.findings.len()
        );
        println!("Only control-file checks ran. No findings does not mean the extension is safe.");
    }
    Ok(())
}

fn print_finding(finding: &Finding) {
    println!(
        "  [{:?}] {}: {}",
        finding.severity, finding.rule_id, finding.title
    );
    match finding.line {
        Some(line) => println!("    File: {}:{line}", finding.file.display()),
        None => println!("    File: {}", finding.file.display()),
    }
    println!("    Details: {}", finding.details);
    println!("    Suggestion: {}", finding.remediation);
    if let Some(reference) = finding.cve_or_ref {
        println!("    Reference: {reference}");
    }
}
