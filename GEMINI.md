# GEMINI.md - Burp Suite Parser for OpenText Application Security

This document outlines the conventions and context for the development of the Burp Suite parser for OpenText Application Security (formerly Fortify SSC).

## Project Overview
The goal is to create a Java-based plugin for Fortify SSC that enables the ingestion and visualization of Burp Suite scan results.

## Technical Stack
- **Language:** Java 11+
- **Build System:** Gradle (using `shadowJar` for fat JAR packaging)
- **Framework:** Fortify Plugin SDK (SPI)
- **Data Formats:** Burp Suite XML/JSON, Fortify Internal Model

## Development Guidelines
- **ID Stability:** Ensure that vulnerability IDs are generated deterministically (e.g., hashing URL, Issue Type, and Parameter) to prevent duplicates across scans.
- **Surgical Changes:** Focus on implementing the SPI interfaces (`ParserPlugin`, `ScanParser`, `IssueParser`) cleanly.
- **Documentation:** Use Javadoc for complex parsing logic.
- **Testing:** Every parser feature must be verified with a unit test using a sample Burp export.

## File Structure Conventions
- `src/main/java`: Plugin implementation.
- `src/main/resources`: `view-template.json` and other static resources.
- `src/main/resources/META-INF/services`: SPI registration.
- `plugin.xml`: Root of the resources or JAR.

## Build and Deploy
- Run `./gradlew shadowJar` to build the plugin.
- The resulting JAR should be uploaded via the SSC Administration UI.
- Scans must be ZIPed with a `scan.info` file containing `engineType=[PLUGIN_ID]`.
