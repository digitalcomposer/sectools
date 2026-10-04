# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-05

### Added
- Initial release with a single `sectools` CLI and eight tools:
  `verify`, `xorkey`, `mailscan`, `webrecon`, `dbexport`, `cvelookup`,
  `pcaptriage`, and `certscan`.
- Shared core: checksum verification, structured findings, evidence writing
  (JSON + Markdown), and Markdown report helpers.
- `--json` and `--evidence DIR` options on every tool.
- Test suite, ruff + mypy configuration, and GitHub Actions CI.

[Unreleased]: https://github.com/digitalcomposer/sectools/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/digitalcomposer/sectools/releases/tag/v0.1.0
