# GitHub Actions Workflows

This directory contains GitHub Actions workflows for continuous integration and release automation.

## Workflows

### CI Workflow (`ci.yml`)

The CI workflow runs on every push and pull request to the `master` branch.

**Triggers:**
- Push to `master` branch
- Pull requests targeting `master` branch

**Jobs:**

1. **Test** - Runs on multiple Go versions (1.24.x and stable)
   - Downloads and verifies Go module dependencies
   - Runs all tests with race detection: `go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...`
   - Uploads code coverage reports as artifacts

2. **Shellcheck** - Validates shell scripts
   - Runs shellcheck on all scripts in `scripts/` directory
   - Uses warning severity level
   - Ensures POSIX compliance

3. **Build Validation** - Verifies compilation
   - Runs after tests and shellcheck pass
   - Builds all three binaries:
     - `netutil` (main TUI application)
     - `ouihelper` (MAC address vendor lookup utility)
     - `netutil-fileserver` (HTTP/HTTPS file server)
   - Verifies binaries can execute basic commands

**Matrix Strategy:**
- Tests against Go 1.24.x (current project version)
- Tests against latest stable Go version

### Release Workflow (`release.yml`)

The release workflow creates production-ready binary distributions when a version tag is pushed.

**Triggers:**
- Push of tags matching `v*` pattern (e.g., `v1.0.0`, `v2.1.3`)

**Build Matrix:**
- **OS:** Linux
- **Architectures:** amd64, arm64

**Jobs:**

1. **Build Release Binaries**
   - Compiles binaries for each OS/architecture combination
   - Uses `-ldflags="-s -w"` to reduce binary size
   - Creates release structure:
     ```
     netutility/
     ├── netutil              # Main TUI binary
     ├── bin/
     │   ├── ouihelper       # MAC lookup utility
     │   └── netutil-fileserver  # File server
     └── scripts/            # Complete script collection
     ```
   - Creates compressed archives (`.tar.gz`)
   - Generates SHA256 checksums for verification

2. **Create GitHub Release**
   - Creates a GitHub release for the tag
   - Generates release notes automatically from commits
   - Attaches all binary archives and checksums
   - Makes release publicly available

**Release Artifacts:**
- `netutility-v*.*.* -linux-amd64.tar.gz`
- `netutility-v*.*.* -linux-arm64.tar.gz`
- Corresponding `.sha256` checksum files

## Creating a Release

To create a new release:

1. Ensure all changes are committed and pushed to `master`
2. Create and push a version tag:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. GitHub Actions will automatically:
   - Build binaries for all target platforms
   - Create a GitHub release
   - Attach binary artifacts

## Verifying Releases

To verify a downloaded release:

```bash
# Download both the archive and checksum
wget https://github.com/fortifyde/NetUtility/releases/download/v1.0.0/netutility-v1.0.0-linux-amd64.tar.gz
wget https://github.com/fortifyde/NetUtility/releases/download/v1.0.0/netutility-v1.0.0-linux-amd64.tar.gz.sha256

# Verify checksum
sha256sum -c netutility-v1.0.0-linux-amd64.tar.gz.sha256
```

## Development Tips

### Running Tests Locally

Before pushing, run the same tests that CI runs:

```bash
# Run all tests with race detection
go test -v -race ./...

# Run shellcheck on scripts
shellcheck scripts/**/*.sh

# Verify builds
go build -v ./cmd/netutil
go build -v ./cmd/ouihelper
go build -v ./cmd/fileserver
```

### Code Coverage

View coverage reports:

```bash
# Generate coverage
go test -coverprofile=coverage.txt -covermode=atomic ./...

# View HTML coverage report
go tool cover -html=coverage.txt
```

### Testing Release Process Locally

You can test the release build process locally:

```bash
# Build for specific platform
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o netutil ./cmd/netutil
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/ouihelper ./cmd/ouihelper
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/netutil-fileserver ./cmd/fileserver

# Create release structure
mkdir -p release/netutility/bin
cp netutil release/netutility/
cp bin/* release/netutility/bin/
cp -r scripts release/netutility/

# Create archive
cd release
tar -czf netutility-test-linux-amd64.tar.gz netutility
```

## Troubleshooting

### Tests Failing in CI but Passing Locally

- Ensure you're testing with the correct Go version (1.24.x)
- Check for race conditions: `go test -race ./...`
- Verify your code works on Linux (workflows run on `ubuntu-latest`)

### Shellcheck Warnings

Shellcheck enforces POSIX compliance and best practices:
- Avoid bashisms (use `/bin/sh` compatible syntax)
- Quote variables to prevent word splitting
- Check for common scripting errors

### Release Workflow Not Triggering

- Ensure tag follows the pattern `v*` (e.g., `v1.0.0`, not `1.0.0`)
- Verify tag was pushed: `git push origin --tags`
- Check GitHub Actions tab for workflow run status

### Binary Size Too Large

If binaries are unexpectedly large:
- Verify `-ldflags="-s -w"` is being used (strips debug info)
- Check for embedded resources that might be included
- Consider using `upx` for additional compression if needed

## Security Considerations

### Secrets

The workflows use `GITHUB_TOKEN` which is automatically provided by GitHub Actions. No additional secrets need to be configured for basic operation.

### Permissions

The release workflow requires `contents: write` permission to create releases and upload artifacts.

### Artifact Retention

Coverage reports are retained for 7 days to save storage while providing recent history for debugging.

## Further Reading

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Go GitHub Actions Guide](https://docs.github.com/en/actions/use-cases-and-examples/building-and-testing/building-and-testing-go)
- [Creating Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
