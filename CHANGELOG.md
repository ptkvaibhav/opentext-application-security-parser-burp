# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-04-20
### Added
- Enterprise-grade readiness: added comprehensive JavaDoc documentation across the codebase.
- Improved `README.md` with professional headers, badges, and detailed integration instructions.
- Addressed all outstanding Dependabot alerts by updating `junit-jupiter` to v5.11.4 and verifying component security.
- Updated GitHub Actions CI and CodeQL workflows to use the latest supported versions (`v4` and `v3` respectively) fixing previously failing CI runs.
### Removed
- Cleaned up the repository by removing the redundant and untracked `temp-sample-parser` directory.

## [1.2.6] - 2026-04-20
### Fixed
- Fixed the persistent "Loading issue details" hang in Fortify SSC by completely refactoring `ViewTemplate.json` to follow the standard array-of-arrays format and correctly using the `customAttributes.` prefix.
- Aligned custom attribute mapping keys with the internal SSC model to ensure UI data binding succeeds.

## [1.2.5] - 2026-04-20
### Fixed
- Fixed "Loading issue details" hang in Fortify SSC by ensuring all custom attributes are non-null (returning empty strings instead of null).
- Improved view template compatibility by simplifying the issue details layout to use the `SIMPLE` template ID.
- Corrected a syntax error in the internal `mapImpact` logic.

## [1.2.4] - 2026-04-20
### Fixed
- Fixed `FMDALException` during scan ingestion by adding robust truncation for all string fields and custom attributes.
- Fixed potential SQL execution failures by implementing duplicate issue ID prevention within a single scan session.
- Fixed missing vulnerability metadata by mapping additional standard fields: `vulnerabilityAbstract`, `confidence`, and `impact`.

## [1.2.3] - 2026-04-20
### Fixed
- Fixed classloader conflicts in Fortify SSC by relocating Jackson dependencies to `com.fortify.plugin.burp.shadow.jackson`.
- Improved XML parsing robustness to handle both `<issues>` and `<items>` root elements more reliably using Jackson annotations.
- Added deterministic ID generation safety checks to prevent potential `NullPointerExceptions` during scan ingestion.

### Added
- Added SLF4J logging throughout the parsing process to provide better diagnostics in the Fortify SSC plugin logs.
- Added more comprehensive unit tests for XML unmarshalling and edge cases in host attribute parsing.

## [1.2.2] - 2026-04-07
### Fixed
- Fixed `FMDALException` in Fortify SSC caused by unique ID length and format by switching from Base64-encoded SHA-256 to a 32-character MD5 hex string.
- Fixed `FMDALException` caused by `fileName` exceeding 255 characters by truncating the `fileName` field.

## [1.2.1] - 2026-04-06
### Fixed
- Fixed critical `ScanParsingException` leading to "No valid analysis result was found" in Fortify SSC. The plugin now properly invokes `scanBuilder.completeScan()` to trigger Fortify's internal processing logic.

## [1.2.0] - 2026-04-06
### Fixed
- Fixed `plugin.xml` parsing error in Fortify SSC by conforming strictly to the `pluginmanifest-1.0.xsd` schema and correct XML namespaces.
- Fixed an issue where `.XML` files with uppercase extensions were rejected by using case-insensitive extension matching.
- Added robust error reporting when no valid XML file is found instead of failing silently.

### Added
- Added support for parsing Burp Reports `<issues>/<issue>` structure, in addition to the standard `<items>/<item>` structure.
- Added official Fortify SSC icons and logos for the plugin UI.
- Relocated the ViewTemplate configuration to align with Fortify reference project conventions.

## [1.0.0] - 2026-04-06
### Added
- Initial production-ready release of the Burp Suite parser for OpenText Application Security (Fortify SSC).
- Full support for Burp Suite XML exports.
- Deterministic vulnerability ID generation (SHA-256).
- Custom attribute mapping for detailed Burp issue metadata.
- Automated CI/CD with GitHub Actions.
- Security scanning with CodeQL and Dependabot.

### Changed
- Upgraded to Java 17 for modern runtime compatibility.
- Upgraded build infrastructure to Gradle 9.4.1.
- Migrated to `com.gradleup.shadow` plugin for robust artifact packaging.
- Updated all dependencies to their latest secure versions (Jackson 2.18, JUnit 6.0, Mockito 5.23).
