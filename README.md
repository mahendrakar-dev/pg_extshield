# pg_extshield

Check PostgreSQL extension files for possible configuration and security concerns.

- **CLI:** scan a folder from your terminal.
- **MCP server:** let an AI assistant call the same scanner.

This is a standalone Rust tool, not a PostgreSQL extension. It reads files
without loading or executing the extension. You do not need PostgreSQL or pgrx
installed to use it.

**Release status: 0.1.0-alpha.1 (experimental).** Currently, only primary
`.control` files are checked. Rules and report formats may change.

## Installation

Requires a recent stable Rust toolchain and Cargo. From the project folder:

```bash
cargo build --release --locked
```

The executable is created at `target/release/pg_extshield` on Linux.

## Usage

Pass the folder containing the extension's primary control file:

```bash
./target/release/pg_extshield scan /path/to/extension
```

For example, a folder containing `demo.control`:

```text
demo/
├── demo.control
├── sql/
└── src/
```

The report includes rule IDs, severity, file locations, explanations, and
suggested actions. To see the available commands:

```bash
./target/release/pg_extshield --help
./target/release/pg_extshield scan --help
```

### Current checks

| Rule | Level | What it reports |
|---|---|---|
| `CTL-001` | Low | A trusted extension that requires superuser installation and has no fixed schema. This asks for review; it does not prove a vulnerability. |
| `CTL-003` | Medium | A missing or empty default version. This is a configuration issue, not a security vulnerability. |

The scanner reports invalid settings and read errors instead of silently
ignoring them. It stops at the first error and does not print a partial report.

Exit codes:

- `0`: the command completed, even if findings were reported or no files matched.
- `1`: scanning failed.
- `2`: invalid command-line arguments.

## MCP setup

The server communicates through standard input and output. No HTTP port is needed.
Your MCP client starts the executable with the `mcp` argument.

For clients using the `mcpServers` configuration format:

```json
{
  "mcpServers": {
    "pg-extshield": {
      "type": "stdio",
      "command": "/absolute/path/to/pg_extshield/target/release/pg_extshield",
      "args": ["mcp"]
    }
  }
}
```

Replace the command path with your executable's absolute path. For the VS Code
`.vscode/mcp.json` format, use `servers` instead of `mcpServers`. You can also
register the command through **MCP: Add Server**.

In WSL, start the server in the Linux environment where the executable lives.
The server reads files using its operating system user's permissions; it does
not restrict scans to a workspace.

Available tools:

| Tool | Input | Result |
|---|---|---|
| `server_status` | None | Confirms that the server responds. Does not scan files. |
| `scan_extension` | `path`: extension folder path | Returns scanned files, skipped files, findings, rules checked, and notes. |

Example assistant request:

> Use pg-extshield's scan_extension tool to scan `/path/to/extension`.

Scan failures return MCP tool errors. An empty folder produces a report that
clearly states that no checks ran. Inspect the actual tool result, not just
the assistant's answer.

After changing code, rebuild the executable and restart the MCP server.
Do not print debug messages to stdout in MCP mode; use stderr instead.

## Important notes

- No findings does **not** mean the extension is safe.
- Only primary control files directly inside the supplied folder are checked.
- Subfolders and symbolic-link entries are not scanned.
- Version-specific files such as `demo--1.1.control` are reported as skipped.
- SQL, Rust/C source, compiled libraries, and database permissions are not checked.
- Version comparisons, SQL checks, and binary checks are future work.
- Source placeholders such as `@CARGO_VERSION@` are preserved. The scanner does
  not yet verify that packaging has replaced them.

## Project structure

```text
pg_extshield/
├── Cargo.toml        # Package details and dependencies
├── Cargo.lock        # Locked dependency versions
├── README.md         # Setup and usage
├── src/
│   ├── lib.rs        # Control-file parser, rules, and shared types
│   ├── scan.rs       # File scanning and report data; no printing
│   └── main.rs       # CLI commands, MCP tools, and output
└── tests/
    ├── control.rs   # Parser and rule tests
    └── cli.rs       # CLI tests and MCP calls over stdin/stdout
```

Both the CLI and MCP server use the same scanning function.

## Testing

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Tests cover parsing, rules, CLI output, and MCP requests and results.
They use temporary test folders and do not need a database.

## License

MIT, as declared in [Cargo.toml](Cargo.toml).
