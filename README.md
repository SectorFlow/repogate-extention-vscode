# RepoGate VS Code Extension

RepoGate is a powerful VS Code extension that acts as a security gatekeeper for your project's dependencies. It monitors dependency changes and validates them against your organization's security policies through the RepoGate API.

## Features

- **📦 Initial Package Scan**: Automatically scans all existing dependencies on first install and sends to RepoGate platform
- **🔍 Real-time Dependency Monitoring**: Watches `package.json` (npm), `pom.xml` (Maven), and `build.gradle` (Gradle) files for changes
- **✅ Security Validation**: Validates new dependencies against your security policies via RepoGate API
- **🚨 Non-blocking Notifications**: Alerts you of denied packages without interrupting your workflow
- **📊 Problems Panel Integration**: Shows dependency status directly in VS Code Problems panel
- **🔄 Continuous Status Polling**: Polls every 10 seconds for approval status updates
- **🗑️ Removal Detection**: Automatically notifies platform when denied packages are removed
- **🔐 Secure Token Storage**: Uses VS Code SecretStorage for API token security
- **📈 Status Bar Indicator**: Shows real-time connection status and pending/denied counts
- **📝 Output Channel**: Detailed logging with sensitive data sanitization

## Installation

### From VSIX File

1. Download the latest `.vsix` file
2. Open VS Code
3. Go to Extensions (`Ctrl+Shift+X` or `Cmd+Shift+X`)
4. Click the `...` menu → `Install from VSIX...`
5. Select the downloaded file
6. Reload VS Code
 
### From Marketplace

1. Open VS Code
2. Go to Extensions (`Ctrl+Shift+X` or `Cmd+Shift+X`)
3. Search for "RepoGate"
4. Click **Install**

Or install directly from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=repogate.repogate ).

## Quick Start

### 1. Configure API Token

After installation, you'll be prompted to configure your API token:

1. Click "Open Settings" when prompted
2. Or manually: `File` → `Preferences` → `Settings` → Search "RepoGate"
3. Set your **API Token** (will be securely stored)
4. Set your **API URL** (default: `https://api.repogate.io/api/v1`)

### 2. Test Connection

Verify your setup:

1. Open Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`)
2. Run: `RepoGate: Test Connection`
3. Or click **[Test Connection]** link in Settings

### 3. Initial Scan

On first activation, RepoGate will:
- Scan all existing dependencies in your workspace
- Send them to `/queue` endpoint for baseline review
- Start monitoring for changes

## How It Works

### Initialization Flow

1. **First Install**: Extension scans all existing packages and sends to `/queue` endpoint
2. **Baseline Established**: Platform receives inventory of current dependencies
3. **Watchers Start**: File watchers activate only after successful scan
4. **Continuous Monitoring**: Watches for any dependency changes

### When You Add a New Dependency

1. **Detection**: Extension detects change in `package.json`, `pom.xml`, or `build.gradle`
2. **Request**: Sends `POST /dependencies/request` with package info
3. **Polling**: Checks status via `POST /dependencies/check` every 10 seconds
4. **Notification**: Shows approval/denial status
5. **Diagnostics**: Adds entry to Problems panel

### Status Values

| Status | Icon | Meaning | Action |
|--------|------|---------|--------|
| **approved** | ✓ | Package is safe to use | None required |
| **denied** | ❌ | Package is blocked | Remove or revert |
| **pending** | ⏳ | Awaiting security review | Wait for approval |
| **scanning** | 🔍 | Being scanned for vulnerabilities | Wait for results |
| **not_found** | ❓ | Package not in database | Request will be submitted |

### When You Remove a Denied Package

1. **Detection**: Extension detects package removal
2. **Notification**: Sends `POST /dependencies/update` with removal info
3. **Confirmation**: Shows "Platform has been notified" message
4. **Cleanup**: Removes diagnostic from Problems panel

## Commands

Access via Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`):

- **RepoGate: Test Connection** - Test API connectivity and authentication
- **RepoGate: Scan Now** - Manually scan all packages and send to `/queue`
- **RepoGate: Show Output** - Open RepoGate log output channel
- **RepoGate: Clear Diagnostics** - Clear all diagnostics from Problems panel

## Settings

Configure in VS Code Settings (`Ctrl+,` or `Cmd+,`):

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `repogate.enabled` | boolean | `true` | Enable/disable dependency monitoring |
| `repogate.apiUrl` | string | `https://api.repogate.io/api/v1` | RepoGate API base URL |
| `repogate.apiToken` | string | `""` | API authentication token (migrated to SecretStorage) |
| `repogate.pollIntervalMs` | number | `10000` | Status polling interval (minimum 3000ms) |
| `repogate.includeDevDependencies` | boolean | `true` | Include devDependencies in scans |


## User Interface

### Status Bar

Bottom-right corner shows:
- **$(check) RepoGate** - Connected and monitoring
- **$(sync~spin) RepoGate** - Checking dependencies
- **$(error) RepoGate** - Connection error
- **$(circle-slash) RepoGate** - Disabled (no token)

Counts shown: `RepoGate (2 pending, 1 denied)`

Click to open Output channel.

### Problems Panel

Denied/pending packages appear in Problems panel:
- **Error** (red): Denied packages
- **Warning** (yellow): Pending/not found packages
- **Info** (blue): Scanning packages

### Notifications

- **Approved**: Silent (logged only)
- **Denied**: Error notification with "View Details" button
- **Pending**: Info notification
- **Scanning**: Info notification
- **Removed**: Confirmation notification (for denied packages)

## Requirements

- **VS Code**: 1.85.0 or higher
- **RepoGate API**: Running instance with valid token
- **Network**: Access to RepoGate API server

## Supported Package Managers

| Ecosystem | Files Monitored |
|-----------|----------------|
| **npm** | `package.json` |
| **Maven** | `pom.xml` |
| **Gradle** | `build.gradle`, `build.gradle.kts` |

## Security

- **Token Storage**: API tokens are stored in VS Code SecretStorage (encrypted)
- **Migration**: Tokens in plain settings are automatically migrated to SecretStorage
- **Logging**: Sensitive data (tokens, passwords) is redacted from logs
- **HTTPS**: Use HTTPS API URLs in production

## Troubleshooting

### "No API token configured"

**Solution**: 
1. Open Settings → Search "RepoGate"
2. Set API Token
3. Run "Test Connection" command

### "Connection failed"

**Possible Causes**:
- RepoGate service not running
- Wrong API URL or port
- Invalid API token
- Network/firewall issues

**Solution**:
1. Verify service is running
2. Check API URL in settings
3. Run "Test Connection" command
4. Check Output channel for details

### "Bootstrap failed"

**Cause**: Initial package scan failed

**Solution**:
1. Check API connection
2. Run "Test Connection"
3. Run "Scan Now" to retry

### Packages not being monitored

**Solution**:
1. Check `repogate.enabled` is `true`
2. Verify API token is configured
3. Check Output channel for errors
4. Ensure file is not in `node_modules`

## Known Limitations

- **Manual Installation**: Developers can still install packages via command line (extension monitors but doesn't block)
- **Transitive Dependencies**: Only direct dependencies are monitored
- **Offline Mode**: Requires network connection to API
- **NPM Only**: Maven and Gradle watchers are planned but not yet implemented in v1.6.0

## License

MIT License - See [LICENSE](LICENSE) file.

## Support 
- **Documentation**: https://repogate.io/docs
- **Email**: support@repogate.io

---

**Made with ❤️ for secure software development**
