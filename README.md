# pg_extshield

Check PostgreSQL extension files for possible configuration and security concerns.

- **CLI:** scan a folder from your terminal.
- **MCP server:** let an AI assistant call the same scanner.

This is a standalone Rust tool, not a PostgreSQL extension. It reads files
without loading or executing the extension. You do not need PostgreSQL or pgrx
installed to use it.

**Release status: 0.1.0-alpha.1 (experimental).** Checks primary and
version-specific `.control` files and SQL filenames. Rules and report formats
may change.

## Installation

Requires a recent stable Rust toolchain and Cargo. From the project folder:

```bash
cargo build --release --locked
```

The executable is created at `target/release/pg_extshield` on Linux.

## Usage

Pass the folder containing the extension's primary control file. Use the packaged
layout, not a source tree that still needs build-time file generation:

```bash
./target/release/pg_extshield scan /path/to/extension
```

For example, a folder containing `demo.control`:

```text
demo/
├── demo.control
├── demo--1.0.sql
├── demo--1.0--1.1.sql
└── demo--1.1.control
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
| `CTL-003` | Low / Medium | Missing default: advisory, because explicit `VERSION` is allowed. Empty or invalid default name: configuration issue (Medium). |
| `CTL-004` | Medium | No installation path to a valid configured default, or no installation script at all when the default is omitted. |

The scanner reports invalid settings and read errors instead of silently
ignoring them. It stops at the first error and does not print a partial report.

### Script directories and version paths

When `directory` is omitted, scripts and secondary controls are looked for beside
the primary control. Absolute directory paths are used directly.

An explicit **relative** `directory` requires an installation base:

```bash
./target/release/pg_extshield scan /opt/postgres/share/extension \
  --installation-base /opt/postgres/share
```

For `directory = 'demo_sql'`, this inventories `/opt/postgres/share/demo_sql`,
not `/opt/postgres/share/extension/demo_sql`. The base is PostgreSQL's `SHAREDIR`
or the corresponding custom `extension_control_path` base. The scanner does not
guess this from a source folder, query a server, or search `extension_control_path`.
Relative command-line paths are interpreted from the process working directory;
absolute paths are recommended, especially for MCP.

This follows the PostgreSQL 18 implementation of
[`get_extension_script_directory`](https://github.com/postgres/postgres/blob/19a2002b5db959e095926d74d46be4b8aa7f20a2/src/backend/commands/extension.c#L567).
The official documentation's control-folder-relative wording differs from that
implementation for an explicitly relative `directory`.

The scanner inventories `extension--version.sql` installation scripts and
`extension--from--to.sql` directed update scripts. For example, default `1.2`
can be reached using `demo--1.0.sql`, `demo--1.0--1.1.sql`, and
`demo--1.1--1.2.sql`; a direct `demo--1.2.sql` is not required. Cycles without
an installation script do not provide a fresh installation path.

Version names are opaque, case-sensitive labels, not SemVer. Empty names, `--`,
leading/trailing `-`, and native directory separators are invalid. No ordering
or downgrade requirement is imposed. Malformed script/secondary filenames are
reported as skipped and do not contribute to paths.

Each known version (from scripts, secondary controls, or a valid default) is
checked with the primary settings plus only its own optional
`extension--version.control` overrides from the script directory. Overrides do
not carry forward between versions. Secondary controls cannot set `directory`
or `default_version`; schema/relocatable conflicts are checked after merging.
Findings retain the supplying setting's file and line and identify the affected
version. The primary baseline is checked on its own if no versions are known.

The report's `extensions` array records each primary control, resolved script
directory, inventoried scripts, default, and per-version checks. A version's
`installation_path` is one shortest candidate path including its starting
installation version, or `null` when no path exists. It is not a guarantee of
PostgreSQL's tie-breaking choice, script execution success, or dependency
availability. Non-default unreachable versions are visible in this array but
do not produce a `CTL-004` finding by themselves.

Missing installation-base input, missing/inaccessible script directories, and
matching script/secondary entries that are not regular files cause explicit scan
errors. They are not reported as missing installation paths. Primary symlink
entries are skipped; matching script/secondary symlinks are not followed.

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
| `scan_extension` | `path`: extension folder path; optional `installation_base` (required for relative `directory`) | Returns scanned controls, script inventories, version paths, skipped files, findings, rules checked, and notes. |

Example assistant request:

> Use pg-extshield's scan_extension tool to scan `/path/to/extension`.

Scan failures return MCP tool errors. An empty folder produces a report that
clearly states that no checks ran. Inspect the actual tool result, not just
the assistant's answer.

After changing code, rebuild the executable and restart the MCP server.
Do not print debug messages to stdout in MCP mode; use stderr instead.

## Important notes

- No findings does **not** mean the extension is safe.
- Primary controls are discovered directly inside the supplied folder. Only their
  resolved script directories are additionally inventoried, without recursion.
- Unpaired secondary controls or those outside the resolved script directory are
  reported as skipped, not audited in isolation.
- SQL contents, Rust/C source, compiled libraries, dependency availability, and
  database permissions are not checked. Nothing from the extension is executed.
- Source placeholders such as `@CARGO_VERSION@` are preserved and used literally
  for filename matching. Build/package first; no template substitution is done.
- Control text and relevant filenames must be valid UTF-8. This is not a full
  PostgreSQL control-setting or SQL validator.

## Project structure

```text
pg_extshield/
├── Cargo.toml        # Package details and dependencies
├── Cargo.lock        # Locked dependency versions
├── README.md         # Setup and usage
├── src/
│   ├── lib.rs        # Control-file parser, rules, and shared types
│   ├── scan.rs       # Script inventory, version paths, and reports; no printing
│   └── main.rs       # CLI commands, MCP tools, and output
└── tests/
    ├── control.rs   # Parser and rule tests
    └── cli.rs       # Scanner/CLI tests and MCP calls over stdin/stdout
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
