# Contributing to orb (orb)

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment for all contributors

## Getting Started

### Prerequisites

- Rust 1.90 (nightly) or later
- Git
- Basic familiarity with HTTP protocols

### Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/orb.git
   cd orb
   ```

3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/WalshyDev/orb.git
   ```

4. Install dependencies and test:
   ```bash
   make build
   make test
   ```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/my-new-feature
# or
git checkout -b fix/bug-description
```

### 2. Make Changes

- Write clean, idiomatic Rust code
- Follow existing code style
- Add tests for new functionality

### 3. Test Your Changes

```bash
# Run all tests
make test

# Fix linting issues
make fix
```

### 4. Commit Your Changes

Write clear, descriptive commit messages:

```bash
git add .
git commit -m "Add feature: brief description

Longer description if needed explaining:
- Why this change is necessary
- What problem it solves
- Any breaking changes"
```

Commit message guidelines:
- Keep first line under 72 characters
- Reference issues: "Fixes #123" or "Relates to #456"

### 5. Push and Create PR

```bash
git push origin feature/my-new-feature
```

Then create a Pull Request on GitHub.

## Pull Request Guidelines

### PR Description Should Include

- **Summary**: Brief description of changes
- **Motivation**: Why is this change needed?
- **Changes**: List of specific changes made
- **Testing**: How was this tested?
- **Breaking Changes**: Any breaking changes?
- **Related Issues**: Fixes #123

### PR Template

```markdown
## Summary
Brief description of the change.

## Motivation
Why is this change necessary? What problem does it solve?

## Changes
- Change 1
- Change 2
- Change 3

## Testing
How have you tested these changes?
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Breaking Changes
List any breaking changes or "None"

## Related Issues
Fixes #123
```

### PR Checklist

Before submitting, ensure:

- [ ] Code compiles without warnings
- [ ] All tests pass (`make test`)
- [ ] Code is formatted (`make fix`)
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] No unnecessary dependencies added

## Code Style

### Rust Style

Follow the [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/):

```rust
// Good
pub fn execute_request(args: &Args) -> Result<RequestResult> {
    let client = build_client(args)?;
    let response = client.send().await?;
    Ok(response)
}

// Use descriptive names
let content_type = response.headers().get(CONTENT_TYPE);

// Prefer early returns
if args.silent {
    return Ok(());
}

// Document public APIs
/// Executes an HTTP request based on the provided arguments.
///
/// # Arguments
/// * `args` - The CLI arguments containing request configuration
///
/// # Returns
/// * `Ok(RequestResult)` - The successful HTTP response
/// * `Err(anyhow::Error)` - Any error that occurred
pub fn execute_request(args: &Args) -> Result<RequestResult> {
    // ...
}
```

### Error Handling

- Use `anyhow::Result` for application errors
- Provide context with `.context()`
- Use `?` for error propagation

```rust
// Good
let file = std::fs::read(path)
    .context(format!("Failed to read file: {}", path))?;

// Avoid
let file = std::fs::read(path).unwrap();
```

### Testing Style

```rust
#[test]
fn test_parse_basic_auth() {
    let args = Args::try_parse_from(&[
        "orb",
        "https://example.com",
        "-u",
        "user:pass"
    ]).unwrap();

    assert_eq!(args.user.unwrap(), "user:pass");
}
```

## Project Structure

### Adding New Features

1. **CLI Options** (`src/cli.rs`):
   - Add field to `Args` struct
   - Add clap attribute with documentation
   - Add to help text

2. **Client Logic** (`src/client.rs`):
   - Implement logic in `build_client()` or `build_request()`
   - Handle errors appropriately
   - Add comments for complex logic

3. **Output Handling** (`src/output.rs`):
   - Add display logic if needed
   - Handle new response formats

4. **Tests**:
   - Add unit test in `tests/unit_tests.rs`
   - Add integration test in `tests/integration_tests.rs`
   - Test edge cases

5. **Documentation**:
   - Update README.md with examples
   - Update help text
   - Add example if complex

## Testing

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test test_name

# With output
cargo test -- --nocapture

# Integration tests only
cargo test --test integration_tests

# Unit tests only
cargo test --lib
cargo test --test unit_tests
```

### Writing Tests

Test a feature:
```rust
#[test]
fn test_get_request() {
    let server = MockServer::start();

    let mock = server.mock(|when, then| {
        when.method(GET).path("/test");
        then.status(200).body("OK");
    });

    let mut cmd = cargo::cargo_bin!("orb").unwrap();
    cmd.arg(server.url("/test"));

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    mock.assert();
}
```

If you want to test multiple cases, use parameterized tests.
```rust
#[test_case("user:password", "dXNlcjpwYXNzd29yZA=="; "with password")]
#[test_case("user", "dXNlcjo="; "without password")]
fn test_basic_auth(user_arg: &str, expected_header: &str) {
    let server = MockServer::start();

    let mock = server.mock(|when, then| {
        when.method(GET).path("/test").header(
            "Authorization",
            format!("Basic {}", expected_header).as_str(),
        );
        then.status(200).body("OK");
    });

    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/test")).arg("-u").arg(user_arg);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    mock.assert();
}
```

## Documentation

### Code Documentation

- Document all public APIs with `///`
- Include examples in doc comments
- Explain non-obvious logic with `//`

```rust
/// Builds an HTTP client with the specified configuration.
///
/// # Arguments
/// * `args` - CLI arguments containing client configuration
///
/// # Returns
/// * `Ok(Client)` - A configured reqwest client
/// * `Err(anyhow::Error)` - Configuration error
///
/// # Examples
/// ```rust
/// let args = Args::default();
/// let client = build_client(&args)?;
/// ```
fn build_client(args: &Args) -> Result<Client> {
    // Implementation
}
```

### User Documentation

- Update README.md for user-facing changes
- Add examples for new features
- Keep documentation concise and clear

## Release Process

Releases are automated via GitHub Actions when tags are pushed:

1. Update version in `Cargo.toml`
3. Commit: `git commit -m "Release v1.2.3"`
4. Tag: `git tag v1.2.3`
5. Push: `git push origin main --tags`

GitHub Actions will:
- Run all tests
- Build binaries for all platforms
- Create GitHub release

## Issue Guidelines

### Reporting Bugs

Include:
- orb version (`orb --version`)
- Operating system
- Command that failed
- Expected vs actual behavior
- Error messages/stack traces

### Feature Requests

Include:
- Use case description
- Proposed solution
- Alternative approaches considered
- Examples of similar features elsewhere

### Questions

- Check existing issues and documentation first
- Provide context about what you're trying to achieve
- Include example code/commands if relevant

## Review Process

### What We Look For

- **Correctness**: Does it work as intended?
- **Tests**: Are changes adequately tested?
- **Style**: Follows project conventions?
- **Documentation**: Updated as needed?
- **Performance**: No unnecessary performance degradation?
- **Breaking Changes**: Justified and documented?

### Timeline

- Initial review: Within 3-5 days
- Follow-up reviews: Within 2 days
- Merge: After approval and CI passes

## Getting Help

- **Questions**: Open a GitHub issue with "Question:" prefix
- **Discussions**: Use GitHub Discussions
- **Security**: Email security issues privately (don't open public issues)

## Recognition

Contributors will be:
- Mentioned in release notes
- Added to GitHub contributors page

Thank you for contributing! 🎉
