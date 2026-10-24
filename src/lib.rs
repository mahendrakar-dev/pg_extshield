//! Read control-file settings and check them for possible problems.
//!
//! Write one setting per line. The `=` sign is optional. Values can be simple
//! names, decimal numbers, or text in single quotes. A `#` starts a comment
//! unless it is inside quotes. Inside quoted text, use `''` or `\'` for a quote.
//! Backslash escapes such as `\n` and `\043` are also supported.
//! Text must be valid UTF-8, including after escapes are read.
//!
//! These checks are for the main control file, not per-version control files.
//! They do not check SQL, database permissions, or compiled extensions.
//! CTL-001 asks for review; it does not prove a security flaw. No findings does
//! not mean the extension is safe. We keep placeholders like `@CARGO_VERSION@`
//! as they are, without checking whether packaging has replaced them.

use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

mod scan;
pub use scan::{ScanError, ScanReport, SkippedFile, scan_extension};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub cve_or_ref: Option<&'static str>,
    pub file: PathBuf,
    pub line: Option<usize>,
    pub title: &'static str,
    pub details: String,
    pub remediation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ControlFile {
    pub path: PathBuf,
    pub entries: BTreeMap<String, (usize, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlError {
    pub file: PathBuf,
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.file.display(), self.line, self.message)
    }
}

impl std::error::Error for ControlError {}

fn control_error(path: &Path, line: usize, message: impl Into<String>) -> ControlError {
    ControlError {
        file: path.to_path_buf(),
        line,
        message: message.into(),
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    // PostgreSQL accepts short forms, but "o" could mean either "on" or "off".
    match value.to_ascii_lowercase().as_str() {
        "t" | "tr" | "tru" | "true" | "on" | "y" | "ye" | "yes" | "1" => Some(true),
        "f" | "fa" | "fal" | "fals" | "false" | "of" | "off" | "n" | "no" | "0" => Some(false),
        _ => None,
    }
}

impl ControlFile {
    pub fn get(&self, key: &str) -> Option<(usize, &str)> {
        self.entries
            .get(key)
            .map(|(line, val)| (*line, val.as_str()))
    }

    /// Return `Ok(None)` if the setting is missing, or an error if it is invalid.
    pub fn get_bool(&self, key: &str) -> Result<Option<(usize, bool)>, ControlError> {
        let Some((line, raw)) = self.get(key) else {
            return Ok(None);
        };
        let Some(value) = parse_bool(raw) else {
            return Err(control_error(
                &self.path,
                line,
                format!("invalid boolean for `{key}`: {raw:?}"),
            ));
        };
        Ok(Some((line, value)))
    }
}

// Read the bytes after a backslash. Return the decoded byte and how many we read.
fn parse_escape(input: &[u8]) -> Result<(u8, usize), &'static str> {
    let Some(&first) = input.first() else {
        return Err("unfinished backslash escape");
    };

    if (b'0'..=b'7').contains(&first) {
        let mut value = 0u8;
        let mut length = 0;
        // Up to three base-8 digits describe one byte, for example \043 is '#'.
        for &digit in input.iter().take(3) {
            if !(b'0'..=b'7').contains(&digit) {
                break;
            }
            // PostgreSQL keeps the last 8 bits if the number exceeds 255.
            value = value.wrapping_mul(8).wrapping_add(digit - b'0');
            length += 1;
        }
        return Ok((value, length));
    }

    let value = match first {
        b'b' => b'\x08',
        b'f' => b'\x0c',
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        other => other,
    };
    Ok((value, 1))
}

fn parse_quoted_value(input: &str) -> Result<(String, &str), &'static str> {
    let bytes = input.as_bytes();
    // Escapes can spell individual bytes. Check UTF-8 after reading the full value.
    let mut value = Vec::new();
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' if bytes.get(index + 1) == Some(&b'\'') => {
                value.push(b'\'');
                index += 2;
            }
            b'\'' => {
                if value.contains(&0) {
                    return Err("NUL is not allowed in a setting value");
                }
                let value =
                    String::from_utf8(value).map_err(|_| "escaped value is not valid UTF-8")?;
                return Ok((value, &input[index + 1..]));
            }
            b'\\' => {
                let (escaped, length) = parse_escape(&bytes[index + 1..])?;
                value.push(escaped);
                index += 1 + length;
            }
            byte => {
                value.push(byte);
                index += 1;
            }
        }
    }
    Err("unterminated single-quoted value")
}

fn parse_unquoted_value(input: &str) -> Result<(String, &str), &'static str> {
    let end = input
        .find(|c: char| c.is_ascii_whitespace() || c == '#')
        .unwrap_or(input.len());
    let value = &input[..end];
    if value.is_empty() {
        return Err("missing setting value");
    }

    let is_name = value.starts_with(|c: char| c.is_alphabetic() || c == '_')
        && value
            .chars()
            .all(|c| c.is_alphanumeric() || "_-.:/".contains(c));
    let is_number = value
        .chars()
        .all(|c| c.is_ascii_digit() || "+-.eE".contains(c))
        && value.parse::<f64>().is_ok();
    if !is_name && !is_number {
        return Err("unsupported unquoted value; use single quotes");
    }
    Ok((value.to_owned(), &input[end..]))
}

fn parse_value(input: &str) -> Result<String, &'static str> {
    let (value, remaining) = if input.starts_with('\'') {
        parse_quoted_value(input)?
    } else {
        parse_unquoted_value(input)?
    };
    let remaining = remaining.trim_start_matches([' ', '\t', '\r']);
    if !remaining.is_empty() && !remaining.starts_with('#') {
        return Err("unexpected text after setting value");
    }
    Ok(value)
}

fn parse_setting(line: &str) -> Result<(&str, String), String> {
    let key_end = line
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(line.len());
    let key = &line[..key_end];
    if !matches!(
        key,
        "directory"
            | "default_version"
            | "module_pathname"
            | "comment"
            | "schema"
            | "relocatable"
            | "superuser"
            | "trusted"
            | "encoding"
            | "requires"
            | "no_relocate"
    ) {
        return Err(format!("unknown control setting: {key:?}"));
    }

    let mut remaining = line[key_end..].trim_start_matches([' ', '\t', '\r']);
    if let Some(after_equals) = remaining.strip_prefix('=') {
        remaining = after_equals.trim_start_matches([' ', '\t', '\r']);
    }
    let value = parse_value(remaining)?;
    if matches!(key, "trusted" | "superuser" | "relocatable") && parse_bool(&value).is_none() {
        return Err(format!("invalid boolean for `{key}`: {value:?}"));
    }
    Ok((key, value))
}

/// Read settings from text, without opening a file or printing.
/// If a setting appears more than once, keep its last value.
/// Stop at the first invalid line, even if a later line would replace it.
pub fn parse_control_str(path: &Path, content: &str) -> Result<ControlFile, ControlError> {
    let mut entries = BTreeMap::new();
    for (index, raw_line) in content.lines().enumerate() {
        let line_number = index + 1;
        if raw_line.contains('\0') {
            return Err(control_error(
                path,
                line_number,
                "NUL is not allowed in a control file",
            ));
        }
        let line = raw_line.trim_matches([' ', '\t', '\r']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) =
            parse_setting(line).map_err(|message| control_error(path, line_number, message))?;
        entries.insert(key.to_owned(), (line_number, value));
    }
    let control = ControlFile {
        path: path.to_path_buf(),
        entries,
    };
    validate_schema(&control)?;
    Ok(control)
}

fn validate_schema(control: &ControlFile) -> Result<(), ControlError> {
    let relocatable = control
        .get_bool("relocatable")?
        .is_some_and(|(_, value)| value);
    if let Some((line, schema)) = control.get("schema") {
        if schema.is_empty() {
            return Err(control_error(
                &control.path,
                line,
                "`schema` must not be empty",
            ));
        }
        if relocatable {
            return Err(control_error(
                &control.path,
                line,
                "`schema` cannot be combined with `relocatable = true`",
            ));
        }
    }
    Ok(())
}

/// CTL-001 asks for review when a trusted extension needs superuser installation
/// and has no fixed schema. CTL-003 reports a missing or empty default version.
/// Neither rule proves a security flaw. These checks do not inspect SQL or
/// who can create objects in a schema.
pub fn audit_control(control: &ControlFile) -> Result<Vec<Finding>, ControlError> {
    let mut findings = Vec::new();

    validate_schema(control)?;
    let is_trusted = match control.get_bool("trusted")? {
        Some((_, value)) => value,
        None => false,
    };
    let requires_superuser = match control.get_bool("superuser")? {
        Some((_, value)) => value,
        None => true,
    };
    let has_fixed_schema = control.get("schema").is_some();

    if is_trusted && requires_superuser && !has_fixed_schema {
        let line = control.get("trusted").map(|(line, _)| line);
        findings.push(Finding {
            rule_id: "CTL-001",
            severity: Severity::Low,
            cve_or_ref: Some("https://www.postgresql.org/docs/current/extend-extensions.html#EXTEND-EXTENSIONS-SECURITY"),
            file: control.path.clone(),
            line,
            title: "Review schema safety for trusted extension installation",
            details: "This extension requires superuser installation, is trusted, and has no fixed installation schema. When an eligible non-superuser installs it through the trusted mechanism, its scripts run as the bootstrap superuser. Unsafe object lookup could use user-controlled objects. These settings alone do not prove a vulnerability.".to_owned(),
            remediation: "Review installation and upgrade SQL for unsafe name lookup, including function and operator matching. Check schema ownership and CREATE permissions. A fixed schema alone does not guarantee safety.",
        });
    }

    let version = control.get("default_version");
    if version.is_none_or(|(_, value)| value.is_empty()) {
        findings.push(Finding {
            rule_id: "CTL-003",
            severity: Severity::Medium,
            cve_or_ref: None,
            file: control.path.clone(),
            line: version.map(|(line, _)| line),
            title: "Control file has no usable `default_version`",
            details: "The default version is missing or empty. `CREATE EXTENSION` without an explicit `VERSION` clause cannot select a valid default version. This is a configuration finding, not a security vulnerability.".to_owned(),
            remediation: "Add `default_version = '...'` to the .control file.",
        });
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn safe_non_relocatable_superuser_control_passes() {
        let content = r#"
            comment = 'Conditional physical standby replay and catch-up time estimates'
            default_version = '0.1.0-alpha.1'
            module_pathname = 'pg_replcompass'
            relocatable = false
            superuser = true
            trusted = false
        "#;
        let ctrl = parse_control_str(&PathBuf::from("pg_replcompass.control"), content).unwrap();
        let findings = audit_control(&ctrl).unwrap();
        assert!(findings.is_empty(), "Expected 0 findings, got {findings:?}");
    }

    #[test]
    fn flags_trusted_and_relocatable_extension() {
        let content = r#"
            default_version = '1.0'
            trusted = true
            relocatable = true
        "#;
        let ctrl = parse_control_str(&PathBuf::from("vuln.control"), content).unwrap();
        let findings = audit_control(&ctrl).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "CTL-001");
        assert_eq!(findings[0].severity, Severity::Low);
    }
}
