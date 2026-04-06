# Changelog

All notable changes to this project will be documented in this file.

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
