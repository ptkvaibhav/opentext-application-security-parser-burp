# Fortify SSC Burp Suite Parser Plugin

![Build Status](https://github.com/ptkvaibhav/opentext-application-security-parser-burp/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Java](https://img.shields.io/badge/Java-17-orange)
![Fortify](https://img.shields.io/badge/Fortify_SSC-19.x+-brightgreen)

An enterprise-grade custom parser plugin for Fortify Software Security Center (OpenText Application Security). This plugin enables seamless ingestion, parsing, and visualization of PortSwigger Burp Suite XML scan results directly within the Fortify SSC dashboard.

## 📖 Overview

Fortify SSC relies on external plugins to support third-party security tools. This plugin implements the modern Fortify Plugin SPI (v1.2.2320.0), bridging the gap between Burp Suite's dynamic analysis exports and Fortify's centralized vulnerability management.

**Key Features:**
- **Deterministic ID Generation:** Uses SHA-256 hashing of Issue Name, Host, Path, and Location to ensure vulnerability IDs remain stable across subsequent scans, preventing duplicates.
- **Rich Attribute Mapping:** Custom attributes ensure that Burp-specific data (e.g., Confidence, Issue Background, Remediation Detail) is fully visible in SSC.
- **Custom View Template:** Includes a tailored UI template (`burp-view.json`) that organizes issue details cleanly within the SSC interface.
- **Enterprise CI/CD:** Fully integrated GitHub Actions workflow for automated testing, linting (Checkstyle), and build packaging.

## 🚀 Getting Started

### Prerequisites
- **Java:** JDK 17.
- **Build Tool:** Gradle 9.4.1.
- **Fortify SSC:** Version 19.x or later (fully compatible with 25.4.0).
- **Burp Suite:** Export capabilities to XML.

### Building the Plugin

The project uses the Gradle Shadow plugin to create a "Fat JAR" required by Fortify.

```bash
# Clone the repository
git clone https://github.com/ptkvaibhav/opentext-application-security-parser-burp.git
cd opentext-application-security-parser-burp

# Build the Fat JAR
./gradlew clean build shadowJar
```

The resulting deployment artifact will be located at:
`build/libs/fortify-ssc-parser-burp-1.1.0.jar`

## ⚙️ Installation & Usage

### 1. Install into Fortify SSC
1. Log in to your Fortify SSC instance with Administrator privileges.
2. Navigate to **Administration > Plugins > Parsers**.
3. Click **Add** and upload the `fortify-ssc-parser-burp-1.1.0.jar` file.
4. **Important:** After uploading, locate the "Burp Suite Parser Plugin" in the list and click **Enable**.

### 2. Uploading Scan Results
Fortify SSC requires uploaded artifacts to specify their engine type.

1. Export your Burp Suite scan results in **XML format** (e.g., `burp-results.xml`).
2. Create a plain text file named `scan.info` in the same directory as your XML file.
3. Add the following exact line to `scan.info`:
   ```text
   engineType=BURP
   ```
4. Create a ZIP archive (e.g., `results.zip`) containing both `burp-results.xml` and `scan.info`.
5. Upload `results.zip` to your chosen Application Version in Fortify SSC.

## 🛠️ Development & Architecture

- **`BurpParserPlugin.java`**: The main entry point implementing `ParserPlugin<T>`. Handles generic scan mapping and iteration.
- **`BurpItems.java` / `BurpItem.java`**: Jackson XML data models representing the Burp export structure.
- **`BurpVulnerabilityAttribute.java`**: Enum defining custom fields presented in the SSC UI.

### Code Quality
The project enforces strict code quality standards:
- **Linting:** Run `./gradlew checkstyleMain` to ensure code meets format requirements.
- **Testing:** Run `./gradlew test` to execute JUnit 5 and Mockito tests.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests, report issues, and suggest features.

Please also adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

## 🛡️ Security

For information on supported versions and how to report vulnerabilities, please refer to our [Security Policy](SECURITY.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💬 Support

If you need help or have questions, please check out our [Support Guide](SUPPORT.md).
