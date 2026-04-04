# Contributing to Fortify SSC Burp Suite Parser

First off, thank you for considering contributing to this project! It's people like you that make this tool better for everyone.

## How Can I Contribute?

### Reporting Bugs
This section guides you through submitting a bug report. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

- Use the **Bug Report Template** provided in the repository.
- Explain the problem and include additional details to help maintainers reproduce the problem.

### Suggesting Enhancements
This section guides you through submitting an enhancement suggestion, including completely new features and minor improvements to existing functionality.

- Use the **Feature Request Template** provided in the repository.
- Provide a clear and descriptive title for the issue.

### Pull Requests
The process described here has several goals:
- Maintain code quality.
- Fix problems that are important to users.
- Engage the community in working toward the best possible solutions.

1. Fork the repository and create your branch from `main`.
2. If you've added code that should be tested, add tests (JUnit 5 + Mockito).
3. Ensure the test suite passes (`gradle test`).
4. Ensure your code passes linting (`gradle checkstyleMain`).
5. Update the documentation (README.md, etc.) if applicable.
6. Submit a pull request using the provided **Pull Request Template**.

## Development Setup
- Java 21+
- Gradle 8.x
- Your favorite IDE (IntelliJ IDEA, Eclipse, VS Code).
- See `README.md` for build instructions.