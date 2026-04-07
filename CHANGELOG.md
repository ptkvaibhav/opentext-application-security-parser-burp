# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-04-06
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
