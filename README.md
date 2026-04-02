# Fortify SSC Burp Suite Parser Plugin

This is a custom parser plugin for Fortify Software Security Center (OpenText Application Security) that enables the ingestion and visualization of Burp Suite scan results.

## Prerequisites
- Java 21+
- Fortify SSC 19.x or later (compatible with 25.4.0)
- Gradle 8.x

## Building the Plugin
To build the plugin JAR:
```bash
./gradlew shadowJar
```
The resulting JAR will be located in `build/libs/fortify-ssc-parser-burp-1.0.0.jar`.

## Installation
1. Log in to Fortify SSC as an administrator.
2. Navigate to **Administration > Plugins**.
3. Click **Add** and upload the JAR file.
4. Locate the "Burp Suite Parser Plugin" in the list and click **Enable**.

## Usage
To upload results to SSC:
1. Ensure your Burp Suite export is in XML format.
2. Create a `scan.info` file containing `engineType=BURP`.
3. ZIP the XML file and `scan.info` together.
4. Upload the ZIP file to your SSC Application Version.

## Security and Quality
This project includes:
- **Checkstyle:** Linting using a strict configuration.
- **OWASP Dependency-Check:** Security scanning for dependencies.
- **JaCoCo:** Test coverage reporting.
- **JUnit 5 & Mockito:** Comprehensive unit testing.
