# RepoGate VS Code Extension - Changelog

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
