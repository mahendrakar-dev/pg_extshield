use crate::{ControlError, Finding, audit_control, parse_control_str};
use serde::Serialize;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct SkippedFile {
    pub path: PathBuf,
    pub reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub folder: PathBuf,
    pub scanned_files: Vec<PathBuf>,
    pub skipped_files: Vec<SkippedFile>,
    pub findings: Vec<Finding>,
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
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Control(error) => Some(error),
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

/// Check primary control files directly inside the folder, without printing.
/// Stop at the first error and return no partial report.
pub fn scan_extension(folder: &Path) -> Result<ScanReport, ScanError> {
    let entries =
        std::fs::read_dir(folder).map_err(|error| io_error("cannot open folder", folder, error))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error("cannot read an entry in", folder, error))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| io_error("cannot inspect", &path, error))?;
        if file_type.is_file() && path.extension().is_some_and(|ext| ext == "control") {
            files.push(path);
        }
    }
    files.sort();

    let mut report = ScanReport {
        folder: folder.to_path_buf(),
        scanned_files: Vec::new(),
        skipped_files: Vec::new(),
        findings: Vec::new(),
        rules_checked: Vec::new(),
        notes: vec![
            "Only primary control files directly inside the folder are checked. Subfolders, symbolic-link entries, SQL, source code, and compiled libraries are not checked.",
            "These checks cannot prove an extension is safe. CTL-001 asks for review; CTL-003 checks default version settings.",
        ],
    };

    for path in files {
        // Per-version files inherit settings, so checking them alone is misleading.
        if path
            .file_stem()
            .is_some_and(|name| name.to_string_lossy().contains("--"))
        {
            report.skipped_files.push(SkippedFile {
                path,
                reason: "Version-specific control files need to be combined with the primary control file before checking.",
            });
            continue;
        }

        let content = std::fs::read_to_string(&path)
            .map_err(|error| io_error("cannot read", &path, error))?;
        let control = parse_control_str(&path, &content)?;
        report.findings.extend(audit_control(&control)?);
        report.scanned_files.push(path);
    }

    if report.scanned_files.is_empty() {
        report
            .notes
            .push("No primary .control files found. No checks were run.");
    } else {
        report.rules_checked = vec!["CTL-001", "CTL-003"];
    }
    Ok(report)
}
