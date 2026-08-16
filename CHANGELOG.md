# Changelog

All notable changes to this project are documented here.

## 0.4.0 — 2026-08-16

- Use Git's native matcher for opt-in `.gitignore` support, including nested
  ignore files and negation rules.
- Retain the small root-file fallback when Git is unavailable.

## 0.3.1 — 2026-08-16

- Fixed composite-action YAML parsing for CI inputs.

## 0.3.0 — 2026-08-16

- Added SARIF 2.1.0 reports with stable rule IDs for GitHub Code Scanning.
- Added report-file output and SARIF support to the GitHub Action.

## 0.2.0 — 2026-08-13

- Added a reusable GitHub Action for pull-request and release checks.
- Added simple root `.gitignore` support and TOML configuration defaults.
- Added configurable CI failure thresholds and an example configuration file.

## 0.1.0 — 2026-08-13

- Initial public release.
- Checks for credential-like files, token-shaped strings, and missing community files.
- Text and JSON CLI output, exclusion support, and a zero-runtime-dependency package.
