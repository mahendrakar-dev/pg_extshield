use pg_extshield::{
    ControlFile, Severity, audit_control, parse_control_str, parse_version_control_str,
};
use std::path::Path;

fn parse(content: &str) -> ControlFile {
    parse_control_str(Path::new("demo.control"), content).unwrap()
}

#[test]
fn preserves_quoted_comments_equals_quotes_and_utf8() {
    let control = parse(
        "# heading\r\n\
         comment = 'It''s #1 = café' # actual comment\r\n\
         default_version = '0.1.0'\r\n",
    );
    assert_eq!(control.get("comment"), Some((2, "It's #1 = café")));
    assert_eq!(control.get("default_version"), Some((3, "0.1.0")));
    assert_eq!(control.path, Path::new("demo.control"));
}

#[test]
fn handles_backslash_and_octal_escapes_inside_quotes() {
    let control = parse(r"comment = 'it\'s\\here\n\t\043\303\251' # ignored");
    assert_eq!(control.get("comment"), Some((1, "it's\\here\n\t#é")));
}

#[test]
fn preserves_escape_lengths_and_byte_values() {
    for (input, expected) in [
        (r"\1", "\x01"),
        (r"\12", "\n"),
        (r"\123", "S"),
        (r"\1234", "S4"),
        (r"\18", "\x018"),
        (r"\541", "a"),
        (r"\b\f\n\r\t", "\x08\x0c\n\r\t"),
        (r"\q\8", "q8"),
        (r"\'\\", "'\\"),
        (r"\é", "é"),
        ("''''", "''"),
        ("", ""),
    ] {
        let control = parse(&format!("comment = '{input}' # end"));
        assert_eq!(control.get("comment"), Some((1, expected)), "{input}");
    }
}

#[test]
fn accepts_simple_unquoted_values_and_preserves_case() {
    for value in [
        "demo", "Demo", "_demo", "café", "demo-1.0", "a/b:c", "1", "-2", "+3", ".5", "1e2",
    ] {
        let control = parse(&format!("comment = {value}# end"));
        assert_eq!(control.get("comment"), Some((1, value)), "{value}");
    }
}

#[test]
fn reports_exact_errors_for_incomplete_or_invalid_values() {
    for (input, message) in [
        ("comment = '", "unterminated single-quoted value"),
        ("comment = '\\", "unfinished backslash escape"),
        (
            "comment = 'value' extra",
            "unexpected text after setting value",
        ),
        ("comment = '\\400'", "NUL is not allowed in a setting value"),
        ("comment = '\\303'", "escaped value is not valid UTF-8"),
        ("comment = # absent", "missing setting value"),
        (
            "comment = 1.2.3",
            "unsupported unquoted value; use single quotes",
        ),
        ("comment = 'a''", "unterminated single-quoted value"),
    ] {
        let error = parse_control_str(Path::new("demo.control"), input).unwrap_err();
        assert_eq!(error.message, message, "{input}");
        assert_eq!(error.line, 1, "{input}");
    }
}

#[test]
fn allows_optional_equals_and_last_setting_wins() {
    let control = parse("trusted yes\ntrusted = off\ndefault_version 1.0\n");
    assert_eq!(control.get_bool("trusted").unwrap(), Some((2, false)));
    assert_eq!(control.get("default_version"), Some((3, "1.0")));
    assert_eq!(control.get_bool("superuser").unwrap(), None);
}

#[test]
fn accepts_postgres_boolean_spellings_and_unambiguous_prefixes() {
    for (expected, values) in [
        (
            true,
            &[
                "true", "TRUE", "t", "tr", "tru", "on", "yes", "y", "ye", "1",
            ][..],
        ),
        (
            false,
            &[
                "false", "FALSE", "f", "fa", "fal", "fals", "off", "of", "no", "n", "0",
            ][..],
        ),
    ] {
        for key in ["trusted", "superuser", "relocatable"] {
            for value in values {
                let control = parse(&format!("{key} = '{value}'"));
                assert_eq!(control.get_bool(key).unwrap(), Some((1, expected)));
            }
        }
    }
}

#[test]
fn rejects_malformed_and_unsupported_input_with_file_and_line() {
    for setting in [
        "trusted",
        "trusted =",
        "trusted = # no value",
        "trusted = maybe",
        "trusted = o",
        "trusted = ''",
        "superuser = invalid",
        "relocatable = invalid",
        "comment = 'unfinished",
        "comment = 'unfinished\\",
        "comment = 'done' trailing",
        "comment = first second",
        "comment = \"double quotes\"",
        "comment = 'first\nsecond'",
        "comment = '\\000'",
        "comment = '\\377'",
        "comment = '\0'",
        "default_version = @CARGO_VERSION@",
        "= 'no key'",
        "unknown = true",
        "Trusted = true",
    ] {
        let error = parse_control_str(Path::new("demo.control"), &format!("# header\n{setting}"))
            .expect_err(setting);
        assert_eq!(error.file, Path::new("demo.control"), "{setting}");
        assert_eq!(error.line, 2, "{setting}");
        assert!(
            error.to_string().starts_with("demo.control:2: "),
            "{setting}"
        );
        assert!(!error.message.is_empty(), "{setting}");
    }
}

#[test]
fn invalid_boolean_is_not_hidden_by_a_later_assignment() {
    let error = parse_control_str(Path::new("demo.control"), "trusted = typo\ntrusted = false")
        .unwrap_err();
    assert_eq!(error.line, 1);
}

#[test]
fn rejects_conflicting_or_empty_schema() {
    for content in ["schema = 'app'\nrelocatable = true", "schema = ''"] {
        let error = parse_control_str(Path::new("demo.control"), content).unwrap_err();
        assert_eq!(error.line, 1);
        assert!(error.message.contains("schema"));
    }
}

#[test]
fn trusted_schema_warning_honors_privilege_defaults() {
    for (settings, expected) in [
        ("trusted = true", true),
        ("trusted = true\nsuperuser = true", true),
        ("trusted = true\nrelocatable = false", true),
        ("trusted = true\nrelocatable = true", true),
        ("trusted = true\nsuperuser = false", false),
        ("trusted = false", false),
        ("", false),
        ("trusted = true\nschema = 'app'\nrelocatable = false", false),
    ] {
        let control = parse(&format!("default_version = '1.0'\n{settings}"));
        let findings = audit_control(&control).unwrap();
        assert_eq!(findings.len(), usize::from(expected), "{settings}");
        if expected {
            let finding = &findings[0];
            assert_eq!(finding.rule_id, "CTL-001");
            assert_eq!(finding.severity, Severity::Low);
            assert_eq!(finding.line, Some(2));
            assert_eq!(finding.file, Path::new("demo.control"));
            assert!(finding.details.contains("do not prove a vulnerability"));
            assert!(!finding.cve_or_ref.unwrap().contains("CVE-"));
        }
    }
}

#[test]
fn default_version_check_handles_missing_empty_and_source_template() {
    for (content, expected, line) in [
        ("", true, None),
        ("# default_version = '1.0'", true, None),
        ("default_version = ''", true, Some(1)),
        ("default_version = '1.0'", false, None),
        ("default_version = '@CARGO_VERSION@'", false, None),
    ] {
        let findings = audit_control(&parse(content)).unwrap();
        assert_eq!(findings.len(), usize::from(expected), "{content}");
        if expected {
            assert_eq!(findings[0].rule_id, "CTL-003");
            assert_eq!(
                findings[0].severity,
                if line.is_some() {
                    Severity::Medium
                } else {
                    Severity::Low
                }
            );
            assert_eq!(findings[0].line, line);
            assert!(findings[0].cve_or_ref.unwrap().contains("postgresql.org"));
        }
    }
}

#[test]
fn versions_are_opaque_labels_with_postgres_name_restrictions() {
    for version in [
        "beta",
        "2026-10",
        "0.1.0-alpha.1",
        "1.0+build",
        "1",
        ".",
        "..",
        "  ",
        "café",
    ] {
        let control = parse(&format!("default_version = '{version}'"));
        assert!(audit_control(&control).unwrap().is_empty(), "{version}");
    }
    for version in ["", "-1.0", "1.0-", "1--2", "a/b", "../1.0"] {
        let control = parse(&format!("# header\ndefault_version = '{version}'"));
        let findings = audit_control(&control).unwrap();
        assert_eq!(findings.len(), 1, "{version}");
        assert_eq!(findings[0].rule_id, "CTL-003");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].line, Some(2));
        assert_eq!(findings[0].title, "Invalid default version name");
    }
    let control = parse(r"default_version = 'a\\b'");
    assert_eq!(audit_control(&control).unwrap().is_empty(), !cfg!(windows));
}

#[test]
fn missing_default_is_an_advisory_not_invalid_configuration() {
    let findings = audit_control(&parse("")).unwrap();
    assert_eq!(findings[0].severity, Severity::Low);
    assert!(
        findings[0]
            .details
            .contains("Omitting `default_version` is allowed")
    );
    assert!(findings[0].details.contains("explicit VERSION"));
    assert_eq!(findings[0].line, None);
}

#[test]
fn version_overrides_preserve_provenance_and_do_not_leak_between_versions() {
    let primary = parse("default_version = '2.0'\ntrusted = false\nrequires = 'foo'");
    let v2 = parse_version_control_str(
        &primary,
        Path::new("demo--2.0.control"),
        "# override\ntrusted = true\nrequires = 'bar'",
    )
    .unwrap();
    assert_eq!(v2.get("requires"), Some((3, "bar")));
    assert_eq!(v2.get("default_version"), Some((1, "2.0")));
    assert_eq!(v2.source_path("default_version"), Path::new("demo.control"));
    let findings = audit_control(&v2).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file, Path::new("demo--2.0.control"));
    assert_eq!(findings[0].line, Some(2));

    let v3 = parse_version_control_str(
        &primary,
        Path::new("demo--3.0.control"),
        "comment = 'next release'",
    )
    .unwrap();
    assert_eq!(v3.get_bool("trusted").unwrap(), Some((2, false)));
    assert_eq!(v3.get("requires"), Some((3, "foo")));
    assert!(audit_control(&v3).unwrap().is_empty());
    assert_eq!(primary.get_bool("trusted").unwrap(), Some((2, false)));
}

#[test]
fn secondary_controls_are_validated_after_merging_with_primary() {
    let primary = parse("relocatable = true\ntrusted = true\ndefault_version = '1'");
    let merged = parse_version_control_str(
        &primary,
        Path::new("demo--1.control"),
        "schema = 'app'\nrelocatable = false",
    )
    .unwrap();
    assert!(audit_control(&merged).unwrap().is_empty());

    let error = parse_version_control_str(
        &primary,
        Path::new("demo--1.control"),
        "# invalid inherited combination\nschema = 'app'",
    )
    .unwrap_err();
    assert_eq!(error.file, Path::new("demo--1.control"));
    assert_eq!(error.line, 2);
    assert!(error.message.contains("relocatable"));

    let primary = parse("schema = 'app'");
    let error =
        parse_version_control_str(&primary, Path::new("demo--1.control"), "relocatable = true")
            .unwrap_err();
    assert_eq!(error.file, Path::new("demo.control"));
    assert_eq!(error.line, 1);
}

#[test]
fn secondary_controls_reject_forbidden_or_invalid_assignments() {
    for setting in [
        "directory = 'sql'",
        "default_version = '2.0'",
        "trusted = typo\ntrusted = true",
    ] {
        let error = parse_version_control_str(
            &parse("default_version = '1'"),
            Path::new("demo--1.control"),
            &format!("# header\n{setting}"),
        )
        .unwrap_err();
        assert_eq!(error.file, Path::new("demo--1.control"));
        assert_eq!(error.line, 2);
    }
}

#[test]
fn auditing_a_manually_modified_control_does_not_hide_invalid_booleans() {
    for key in ["trusted", "superuser", "relocatable"] {
        let mut control = parse("default_version = '1.0'");
        control
            .entries
            .insert(key.to_owned(), (4, "typo".to_owned()));
        let error = audit_control(&control).unwrap_err();
        assert_eq!(error.line, 4);
        assert!(error.message.contains(key));
    }
}

#[test]
fn findings_remain_serializable_for_mcp() {
    let findings = audit_control(&parse("trusted = true")).unwrap();
    let json = serde_json::to_value(findings).unwrap();
    assert_eq!(json[0]["rule_id"], "CTL-001");
    assert_eq!(json[0]["severity"], "low");
    assert_eq!(json[0]["line"], 1);
    assert_eq!(json[1]["rule_id"], "CTL-003");
    assert!(json[1]["line"].is_null());
}
