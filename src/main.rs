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
use pg_extshield::{Finding, scan_extension_with_base};

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ScanRequest {
    /// Folder on the server's machine. Use an absolute path to avoid ambiguity.
    path: PathBuf,
    /// SHAREDIR or extension_control_path base. Required for relative directory settings.
    installation_base: Option<PathBuf>,
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
        description = "Check primary and version-specific controls and inventory SQL filenames for installation paths (CTL-001, CTL-003, CTL-004). Relative directory settings require installation_base (SHAREDIR or an extension_control_path base). Returns checked controls, script directories, candidate version paths, skipped files, findings, and limits. Does not read SQL contents or execute extension code. No findings is not proof of safety."
    )]
    async fn scan_extension(
        &self,
        request: Parameters<ScanRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let ScanRequest {
            path,
            installation_base,
        } = request.0;
        // File reading is blocking work, so keep it off the async worker threads.
        let result = tokio::task::spawn_blocking(move || {
            scan_extension_with_base(&path, installation_base.as_deref())
        })
        .await
        .map_err(|error| ErrorData::internal_error(format!("scan worker failed: {error}"), None))?;
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
    /// Check extension controls and filename-based installation paths.
    #[command(after_long_help = "\
Primary controls are discovered directly inside the supplied folder.
Version-specific controls in the resolved script directory override the primary.
Only that script directory is inventoried; there is no recursive search.
Relative directory settings require --installation-base (SHAREDIR or a custom
extension_control_path base). Absolute and omitted directory settings do not.
Matching script/control symlinks cause an explicit verification error.
SQL contents, source code, and compiled libraries are not read or executed.

Exit codes: 0 = command completed, even with findings or no matching files;
1 = scan error; 2 = invalid command-line arguments.
The scan stops at the first error. No partial report is printed.
No findings does not mean an extension is safe.")]
    Scan {
        path: PathBuf,
        /// SHAREDIR or custom extension_control_path base, not its extension subfolder.
        #[arg(long)]
        installation_base: Option<PathBuf>,
    },

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
        Commands::Scan {
            path,
            installation_base,
        } => scan(&path, installation_base.as_deref()),
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
fn scan(folder: &Path, installation_base: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let report = scan_extension_with_base(folder, installation_base)?;
    for skipped in &report.skipped_files {
        println!(
            "Skipped file: {} ({})",
            skipped.path.display(),
            skipped.reason,
        );
    }
    for path in &report.scanned_files {
        println!("Checked control file: {}", path.display());
    }
    for extension in &report.extensions {
        println!(
            "Extension {}: script directory {}",
            extension.name,
            extension.script_directory.display()
        );
        for version in &extension.versions {
            match &version.installation_path {
                Some(path) => println!(
                    "  Version {:?}: candidate installation path {}",
                    version.version,
                    path.join(" -> ")
                ),
                None => println!(
                    "  Version {:?}: no installation path from inventoried scripts",
                    version.version
                ),
            }
        }
    }
    for finding in &report.findings {
        print_finding(finding);
    }

    if report.extensions.is_empty() {
        println!(
            "No primary .control files found in {}. No checks were run.",
            folder.display()
        );
    } else {
        if report.findings.is_empty() {
            println!("No findings from the current control-file and script-filename checks.");
        }
        println!(
            "Scanned {} control file(s); {} finding(s).",
            report.scanned_files.len(),
            report.findings.len()
        );
        println!("No findings does not mean the extension is safe.");
    }
    for note in &report.notes {
        println!("Note: {note}");
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
    if let Some(version) = &finding.version {
        println!("    Version: {version:?}");
    }
    println!("    Suggestion: {}", finding.remediation);
    if let Some(reference) = finding.cve_or_ref {
        println!("    Reference: {reference}");
    }
}
