use crate::{
    ControlError, ControlFile, Finding, Severity, audit_default_version,
    audit_installation_settings, control_error, name_error, parse_control_str,
    parse_version_control_str,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct SkippedFile {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct VersionReport {
    pub version: String,
    pub secondary_control: Option<PathBuf>,
    /// One shortest filename-based path, including the initial install version.
    /// None means no installation path was found, not that SQL was executed.
    pub installation_path: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct ExtensionReport {
    pub name: String,
    pub primary_control: PathBuf,
    pub script_directory: PathBuf,
    pub scripts: Vec<PathBuf>,
    pub default_version: Option<String>,
    pub versions: Vec<VersionReport>,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub folder: PathBuf,
    pub scanned_files: Vec<PathBuf>,
    pub skipped_files: Vec<SkippedFile>,
    pub findings: Vec<Finding>,
    pub extensions: Vec<ExtensionReport>,
    pub rules_checked: Vec<&'static str>,
    pub notes: Vec<&'static str>,
}

#[derive(Debug)]
pub enum ScanError {
    Io {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    Control(ControlError),
    Unverified {
        path: PathBuf,
        reason: String,
    },
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                action,
                path,
                source,
            } => {
                write!(f, "{action} {}: {source}", path.display())
            }
            Self::Control(error) => error.fmt(f),
            Self::Unverified { path, reason } => {
                write!(f, "cannot verify {}: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Control(error) => Some(error),
            Self::Unverified { .. } => None,
        }
    }
}

impl From<ControlError> for ScanError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}

fn io_error(action: &'static str, path: &Path, source: std::io::Error) -> ScanError {
    ScanError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

fn unverified(path: &Path, reason: impl Into<String>) -> ScanError {
    ScanError::Unverified {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn read_entries(folder: &Path) -> Result<Vec<std::fs::DirEntry>, ScanError> {
    let entries =
        std::fs::read_dir(folder).map_err(|error| io_error("cannot open folder", folder, error))?;
    let mut entries = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error("cannot read an entry in", folder, error))?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

fn read_control(path: &Path) -> Result<String, ScanError> {
    std::fs::read_to_string(path).map_err(|error| io_error("cannot read", path, error))
}

fn script_directory(
    control: &ControlFile,
    folder: &Path,
    installation_base: Option<&Path>,
) -> Result<PathBuf, ScanError> {
    let directory = match control.get("directory") {
        None => folder.to_path_buf(),
        Some((_, value)) if Path::new(value).is_absolute() => PathBuf::from(value),
        Some((line, value)) => {
            let base = installation_base.ok_or_else(|| {
                control_error(
                    &control.path,
                    line,
                    "cannot verify relative `directory` without an installation base; supply --installation-base (MCP: installation_base). PostgreSQL resolves it from SHAREDIR or the extension_control_path base, not the control-file folder",
                )
            })?;
            base.join(value)
        }
    };
    std::fs::canonicalize(&directory)
        .map_err(|error| io_error("cannot resolve script directory", &directory, error))
}

#[derive(Default)]
struct Inventory {
    scripts: Vec<PathBuf>,
    installs: BTreeSet<String>,
    updates: BTreeMap<String, BTreeSet<String>>,
    controls: BTreeMap<String, PathBuf>,
    versions: BTreeSet<String>,
}

fn inventory_scripts(
    directory: &Path,
    extension: &str,
    skipped: &mut Vec<SkippedFile>,
) -> Result<Inventory, ScanError> {
    let mut inventory = Inventory::default();
    let prefix = format!("{extension}--");
    for entry in read_entries(directory)? {
        let path = entry.path();
        let suffix = match path.extension().and_then(|ext| ext.to_str()) {
            Some("sql") => ".sql",
            Some("control") => ".control",
            _ => continue,
        };
        let filename = entry.file_name();
        let filename = filename
            .to_str()
            .ok_or_else(|| unverified(&path, "control and script filenames must be valid UTF-8"))?;
        let Some(versions) = filename
            .strip_suffix(suffix)
            .and_then(|stem| stem.strip_prefix(&prefix))
        else {
            continue;
        };
        let versions: Vec<_> = versions.split("--").collect();
        let reason = if versions.len() > if suffix == ".sql" { 2 } else { 1 } {
            Some("too many `--` separators")
        } else {
            versions.iter().find_map(|version| name_error(version))
        };
        if let Some(reason) = reason {
            skipped.push(SkippedFile {
                path,
                reason: format!(
                    "Invalid extension filename: {reason}. Not used in version checks."
                ),
            });
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| io_error("cannot inspect", &path, error))?;
        if !file_type.is_file() {
            return Err(unverified(
                &path,
                "matching script or version-specific control is not a regular file; symbolic-link entries are not followed",
            ));
        }
        inventory
            .versions
            .extend(versions.iter().map(|version| (*version).to_owned()));
        if suffix == ".control" {
            inventory.controls.insert(versions[0].to_owned(), path);
        } else {
            inventory.scripts.push(path);
            match versions.as_slice() {
                [version] => {
                    inventory.installs.insert((*version).to_owned());
                }
                [from, to] => {
                    inventory
                        .updates
                        .entry((*from).to_owned())
                        .or_default()
                        .insert((*to).to_owned());
                }
                _ => unreachable!("filename shape was validated"),
            }
        }
    }
    Ok(inventory)
}

fn installation_paths(inventory: &Inventory) -> BTreeMap<String, Vec<String>> {
    let mut paths = BTreeMap::new();
    let mut pending = VecDeque::new();
    for version in inventory.installs.iter().rev() {
        paths.insert(version.clone(), vec![version.clone()]);
        pending.push_back(version.clone());
    }
    // Multi-source breadth-first search finds shortest paths and stops at cycles.
    while let Some(from) = pending.pop_front() {
        if let Some(targets) = inventory.updates.get(&from) {
            for to in targets {
                if !paths.contains_key(to) {
                    let mut path = paths[&from].clone();
                    path.push(to.clone());
                    paths.insert(to.clone(), path);
                    pending.push_back(to.clone());
                }
            }
        }
    }
    paths
}

fn check_extension(
    control: &ControlFile,
    name: String,
    directory: PathBuf,
    report: &mut ScanReport,
) -> Result<(), ScanError> {
    let mut inventory = inventory_scripts(&directory, &name, &mut report.skipped_files)?;
    let default = control.get("default_version");
    if let Some((_, version)) = default
        && name_error(version).is_none()
    {
        inventory.versions.insert(version.to_owned());
    }
    let paths = installation_paths(&inventory);
    let mut versions = Vec::new();
    if inventory.versions.is_empty() {
        report
            .findings
            .extend(audit_installation_settings(control)?);
    }
    for version in &inventory.versions {
        let secondary = inventory.controls.get(version);
        let effective = match secondary {
            Some(path) => {
                let effective = parse_version_control_str(control, path, &read_control(path)?)?;
                report.scanned_files.push(path.clone());
                effective
            }
            None => control.clone(),
        };
        for mut finding in audit_installation_settings(&effective)? {
            finding.version = Some(version.clone());
            report.findings.push(finding);
        }
        versions.push(VersionReport {
            version: version.clone(),
            secondary_control: secondary.cloned(),
            installation_path: paths.get(version).cloned(),
        });
    }
    report.findings.extend(audit_default_version(control));
    let missing_path = match default {
        Some((_, version)) => name_error(version).is_none() && !paths.contains_key(version),
        None => inventory.installs.is_empty(),
    };
    if missing_path {
        let details = match default {
            Some((_, version)) => format!(
                "No direct installation script or directed update chain from an installation script reaches default version {version:?} in {}.",
                directory.display()
            ),
            None => format!(
                "No valid installation script was found for {name:?} in {}. Update scripts alone cannot support a fresh installation, even with an explicit VERSION.",
                directory.display()
            ),
        };
        report.findings.push(Finding {
            rule_id: "CTL-004",
            severity: Severity::Medium,
            cve_or_ref: Some("https://www.postgresql.org/docs/18/extend-extensions.html#EXTEND-EXTENSIONS-UPDATE-SCRIPTS"),
            file: control.path.clone(),
            line: default.map(|(line, _)| line),
            version: default.map(|(_, version)| version.to_owned()),
            title: "No installation path found",
            details,
            remediation: "Check the packaged script directory. Supply an extension--version.sql installation script and any directed update scripts needed to reach the target version.",
        });
    }
    report.extensions.push(ExtensionReport {
        name,
        primary_control: control.path.clone(),
        script_directory: directory,
        scripts: inventory.scripts,
        default_version: default.map(|(_, version)| version.to_owned()),
        versions,
    });
    Ok(())
}

/// Check controls and SQL filenames without reading or executing SQL.
pub fn scan_extension(folder: &Path) -> Result<ScanReport, ScanError> {
    scan_extension_with_base(folder, None)
}

/// Relative `directory` settings require the installation's SHAREDIR or custom
/// extension_control_path base. Stop at the first error; return no partial report.
pub fn scan_extension_with_base(
    folder: &Path,
    installation_base: Option<&Path>,
) -> Result<ScanReport, ScanError> {
    let root = std::fs::canonicalize(folder)
        .map_err(|error| io_error("cannot open folder", folder, error))?;
    let mut report = ScanReport {
        folder: folder.to_path_buf(),
        scanned_files: Vec::new(),
        skipped_files: Vec::new(),
        findings: Vec::new(),
        extensions: Vec::new(),
        rules_checked: Vec::new(),
        notes: vec![
            "Primary controls are discovered directly inside the supplied folder. Only their resolved script directories are inventoried; there is no recursive search. Symbolic-link file entries are not followed.",
            "SQL filenames describe possible installation paths, not successful execution. SQL contents, dependency availability, source code, database permissions, and compiled libraries are not checked.",
            "Each known version uses the primary settings plus only its own optional overrides. These checks cannot prove an extension is safe.",
            "Version labels are opaque, case-sensitive strings. Source placeholders are used literally; scan the packaged layout to verify installation paths.",
        ],
    };

    let mut secondary_files = Vec::new();
    for entry in read_entries(&root)? {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "control") {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| io_error("cannot inspect", &path, error))?;
        if !file_type.is_file() {
            report.skipped_files.push(SkippedFile {
                path,
                reason:
                    "Not a regular primary control file; symbolic-link entries are not followed."
                        .to_owned(),
            });
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".control"))
            .ok_or_else(|| unverified(&path, "control filenames must be valid UTF-8"))?;
        if name.contains("--") {
            secondary_files.push(path);
            continue;
        }
        if let Some(reason) = name_error(name) {
            return Err(unverified(
                &path,
                format!("invalid extension name: {reason}"),
            ));
        }
        let control = parse_control_str(&path, &read_control(&path)?)?;
        let directory = script_directory(&control, &root, installation_base)?;
        check_extension(&control, name.to_owned(), directory, &mut report)?;
        report.scanned_files.push(path);
    }
    for path in secondary_files {
        if !report.scanned_files.contains(&path)
            && !report
                .skipped_files
                .iter()
                .any(|skipped| skipped.path == path)
        {
            report.skipped_files.push(SkippedFile {
                path,
                reason: "Version-specific control has no matching primary in this scan, or is outside its resolved script directory.".to_owned(),
            });
        }
    }
    report.scanned_files.sort();
    report.scanned_files.dedup();
    report.skipped_files.sort_by(|a, b| a.path.cmp(&b.path));
    if report.extensions.is_empty() {
        report
            .notes
            .push("No primary .control files found. No checks were run.");
    } else {
        report.rules_checked = vec!["CTL-001", "CTL-003", "CTL-004"];
    }
    Ok(report)
}
