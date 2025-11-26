# RepoGate VS Code Extension - Changelog

## v1.10.11 - 2025-11-26

### ✨ New Features

- **Clear All Data Command**: Added `repogate.clearAllData` command for troubleshooting
  - Clears all secrets, globalState, bootstrap state, and diagnostics
  - Modal confirmation to prevent accidental data loss
  - Provides clean slate when extension gets into broken state
  - Prompts user to sign in after clearing

### 🐛 Bug Fixes

- **Sign-in Timeout Protection**: Added 60-second timeout to prevent sign-in from hanging indefinitely
- **Enhanced Sign-in Logging**: Extensive logging throughout authentication flow for better debugging
- **Better Error Handling**: Full error messages with stack traces displayed in both logs and UI
- **Error Visibility**: Sign-in errors now shown in both notifications and modal dialogs

### 🛠️ Technical Changes

- Sign-in commands now show detailed progress in Output panel
- Error states properly reflected in status bar
- Improved error recovery with clear user guidance

---

## v1.10.10 - 2025-11-26

### 🐛 Bug Fixes

- **Auto-detect Auth Mode**: Extension now automatically detects authentication mode from existing tokens
  - Fixes issue where settings page showed "Signed in" but extension showed "Not authenticated"
  - When extension is reinstalled, it now recovers authentication state from stored tokens
  - No need to re-authenticate after extension updates or reinstalls
- **Seamless Recovery**: Extension automatically restores `authMode` to globalState when tokens exist

---

## v1.10.5 - 2025-11-25

### 🔄 Backend Compatibility Update

- **Compatible with Backend Security Fix**: This version is tested and compatible with the backend update that treats package versions as unique entities
- **Complete Version-Based Security**: Extension (v1.10.4 changes) + Backend (v1.10.5 compatibility) now provide complete version-aware security
- **What This Means**:
  - `bluebird@1.2.0` and `bluebird@5.2.9` are treated as completely separate packages
  - Each version requires independent security approval
  - Backend now checks name + version + ecosystem when determining approval status
  - No more version bypass vulnerabilities

### 📋 Recommended Upgrade Path

1. Deploy updated backend (includes version-aware approval checks)
2. Install extension v1.10.5
3. Test version change detection with any package

---

## v1.10.4 - 2025-11-25

### 🔒 Critical Security Enhancement

- **Version Change Detection**: Extension now detects **all package version changes** (upgrades and downgrades) and submits them for security review
- **Why This Matters**:
  - New versions can introduce new vulnerabilities
  - Supply chain attacks can compromise specific versions
  - License changes between versions can violate company policy
  - Downgrading to vulnerable versions is now caught
- **What Changed**:
  - Changing `"lodash": "4.17.20"` → `"lodash": "4.17.21"` now triggers approval request
  - Works for all ecosystems: npm, Maven, and Gradle
  - Both upgrades and downgrades are treated as new packages requiring review

### 🛠️ Technical Changes

- Updated `NpmDependencyParser` to track package name + version (not just name)
- Updated `MavenDependencyParser` to detect version changes
- Updated `GradleDependencyParser` to detect version changes
- Added `extractDependenciesWithVersions()` method to all parsers
- Version comparison now triggers approval workflow

---

## v1.10.3 - 2025-11-25

### ✨ New Features

- **Enhanced Denied Package Notifications**: Notifications now show detailed information including:
  - Package name, version, and ecosystem
  - Exact file location where the package is declared
  - Reason for denial (security policy, vulnerability, etc.)
- **View Full Report**: New button to see a comprehensive report in the Output panel with all denied packages and their details
- **Copy Details**: New button to copy the full denied packages report to clipboard for sharing with team or documentation
- **Better Visual Layout**: Improved notification formatting with clear separation between packages and their details

### 🛠️ Technical Changes

- Updated backend to return `packageDetails` array with full package information
- Enhanced `HeartbeatResponse` interface to include `DeniedPackageDetail` type
- Improved `handleDeniedPackagesAlert` to display rich package information
- Maintained backward compatibility with existing `packages` array

---

## v1.10.2 - 2025-11-25

### 🐛 Bug Fixes

- **Improved Token Expiration Handling**: Fixed issue where extension would fail to start properly when access token was expired. The extension now gracefully handles expired tokens and automatically attempts refresh on the first API call.
- **Better Error Recovery**: When token refresh fails, the extension now provides clear guidance to the user with a single "Sign In" prompt instead of multiple confusing error messages.
- **Non-Blocking Bootstrap**: Initial dependency scan failures no longer block the extension from starting. Users can retry the scan manually or it will automatically retry on next startup.
- **Reduced Friction**: Eliminated duplicate sign-out prompts and improved the overall authentication flow to minimize interruptions to the developer workflow.

### 🛠️ Technical Changes

- Updated `ensureAuthOrPrompt()` to return expired config and let API client handle refresh, preventing blocking on startup
- Improved `handleResponseError()` in API client to clear auth state and provide clear error messages when refresh fails
- Enhanced bootstrap error handling with user-friendly retry options
- Removed automatic sign-out from `refreshToken()` to prevent multiple simultaneous sign-out prompts

---

## v1.10.0 - 2025-11-24

This version introduces a complete overhaul of the Microsoft Entra ID authentication flow to provide persistent sessions and a seamless developer experience.

## ✨ New Features

- **Persistent Authentication**: Implemented the full OAuth 2.0 refresh token flow for Microsoft Entra ID. Your authentication session now persists across device restarts and extended periods of inactivity, for up to 90 days.
- **Automatic Token Refresh**: The extension now automatically refreshes your access token in the background, ensuring you stay signed in without interruption.
- **Startup Authentication**: On launch, the extension will automatically attempt to refresh your session if it has expired, getting you back to work faster.
- **Enhanced Security**: Implemented refresh token rotation, where a new refresh token is issued on each refresh, and the old one is invalidated. Refresh tokens are securely stored using encryption.

## 🐛 Bug Fixes

- **Resolved Session Expiration**: Fixed the core issue where authentication sessions would expire after a short period, requiring frequent re-authentication.

## 🛠️ Technical Changes

- **Backend**: 
    - Updated the database schema to securely store encrypted refresh tokens.
    - Overhauled the `/auth/entra/refresh` endpoint to use Microsoft refresh tokens for obtaining new access tokens.
    - The `/auth/entra/callback` endpoint now requests the `offline_access` scope and captures the refresh token.
- **VS Code Extension**:
    - The `authManager` now securely stores and manages both access and refresh tokens.
    - Implemented startup token refresh logic in `ensureAuthOrPrompt()`.
    - The `refreshToken()` method now sends the refresh token to the backend for rotation.
