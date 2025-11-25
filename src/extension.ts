import * as vscode from 'vscode';
import { AuthManager } from './auth/authManager';
import { logger } from './utils/logger';
import { StatusBarManager, RepoGateStatus } from './ui/status/statusBar';
import { DiagnosticsProvider } from './ui/diagnostics/diagnosticsProvider';
import { NotificationManager } from './ui/notifications/notificationManager';
import { BootstrapService } from './services/bootstrap';
import { HeartbeatService } from './services/heartbeatService';
import { NpmWatcher } from './watchers/npmWatcher';
import { MavenWatcher } from './watchers/mavenWatcher';
import { GradleWatcher } from './watchers/gradleWatcher';
import { RepoGateApiClient } from './api/client';

let authManager: AuthManager;
let statusBar: StatusBarManager;
let diagnostics: DiagnosticsProvider;
let notifications: NotificationManager;
let bootstrap: BootstrapService;
let heartbeat: HeartbeatService;
let npmWatcher: NpmWatcher | undefined;
let mavenWatcher: MavenWatcher | undefined;
let gradleWatcher: GradleWatcher | undefined;

export async function activate(context: vscode.ExtensionContext) {
    logger.initialize();
    logger.info('RepoGate extension activating...');

    // Initialize managers
    authManager = new AuthManager(context);
    statusBar = new StatusBarManager();
    diagnostics = new DiagnosticsProvider();
    notifications = new NotificationManager();
    bootstrap = new BootstrapService(context, authManager);
    heartbeat = new HeartbeatService(context, authManager, notifications);

    // Register commands
    registerCommands(context);

    // Check if extension is enabled
    const config = vscode.workspace.getConfiguration('repogate');
    const enabled = config.get<boolean>('enabled', true);

    if (!enabled) {
        logger.info('RepoGate is disabled in settings');
        statusBar.setStatus(RepoGateStatus.DISABLED);
        return;
    }

    // Ensure authentication
    const repoGateConfig = await authManager.ensureAuthOrPrompt();
    if (!repoGateConfig || repoGateConfig.authMode === 'UNAUTHENTICATED') {
        logger.info('Not authenticated, extension will remain passive');
        statusBar.setStatus(RepoGateStatus.DISABLED, 'Not signed in');
        await updateAuthStatus();
        return;
    }

    // Display user info in status bar
    const userInfo = await authManager.getUserInfo();
    if (userInfo) {
        statusBar.setUserInfo(userInfo.email, userInfo.authMode);
    }

    await updateAuthStatus();
    statusBar.setStatus(RepoGateStatus.PENDING, 'Initializing...');

    // Check if bootstrap is needed
    if (!bootstrap.isBootstrapCompleted()) {
        logger.info('First run detected, starting bootstrap...');
        try {
            const success = await bootstrap.bootstrapQueue(repoGateConfig);
            
            if (!success) {
                // Bootstrap failed but don't block extension - it will retry on next activation
                logger.warn('Bootstrap failed, but extension will continue');
                statusBar.setStatus(RepoGateStatus.ERROR, 'Initial scan failed');
                
                // Show a non-blocking notification
                vscode.window.showWarningMessage(
                    'RepoGate: Initial dependency scan failed. The extension will retry on next startup.',
                    'Retry Now',
                    'Dismiss'
                ).then(selection => {
                    if (selection === 'Retry Now') {
                        vscode.commands.executeCommand('repogate.scanNow');
                    }
                });
            }
        } catch (error: any) {
            logger.error('Bootstrap error:', error);
            
            // Check if it's an auth error
            if (error.message && error.message.includes('Authentication expired')) {
                statusBar.setStatus(RepoGateStatus.DISABLED, 'Session expired');
                vscode.window.showWarningMessage(
                    'RepoGate: Your session has expired. Please sign in again.',
                    'Sign In'
                ).then(selection => {
                    if (selection === 'Sign In') {
                        vscode.commands.executeCommand('repogate.signInEntraID');
                    }
                });
                return;
            }
            
            // Other errors - continue but show warning
            statusBar.setStatus(RepoGateStatus.ERROR, 'Initialization error');
        }
    } else {
        logger.info('Bootstrap already completed, skipping...');
    }

    // Start watchers only after successful bootstrap
    await startWatchers(context);

    // Start heartbeat service
    await heartbeat.start();

    statusBar.setStatus(RepoGateStatus.CONNECTED, 'Watching for changes');
    logger.info('RepoGate extension activated successfully');

    // Update status bar with diagnostic counts
    updateStatusBarCounts();
}

/**
 * Start file watchers
 */
async function startWatchers(context: vscode.ExtensionContext) {
    logger.info('Starting file watchers...');

    // Start NPM watcher
    npmWatcher = new NpmWatcher(context, authManager, diagnostics, notifications);
    await npmWatcher.start();

    // Start Maven watcher
    mavenWatcher = new MavenWatcher(context, authManager, diagnostics, notifications);
    await mavenWatcher.start();

    // Start Gradle watcher
    gradleWatcher = new GradleWatcher(context, authManager, diagnostics, notifications);
    await gradleWatcher.start();

    logger.info('File watchers started');
}

/**
 * Register extension commands
 */
function registerCommands(context: vscode.ExtensionContext) {
    // Sign In with EntraID command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.signInEntraID', async () => {
            await signInEntraID();
        })
    );

    // Sign In with API Token command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.signInAPIToken', async () => {
            await signInAPIToken();
        })
    );

    // Sign Out command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.signOut', async () => {
            await signOut();
        })
    );

    // Show Account Info command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.showAccountInfo', async () => {
            await showAccountInfo();
        })
    );

    // Set Token command (legacy)
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.setToken', async () => {
            await setToken();
        })
    );

    // Clear Token command (legacy)
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.clearToken', async () => {
            await clearToken();
        })
    );

    // Test Connection command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.testConnection', async () => {
            await testConnection();
        })
    );

    // Scan Now command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.scanNow', async () => {
            await scanNow();
        })
    );

    // Set API URL command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.setApiUrl', async () => {
            await setApiUrl();
        })
    );

    // Set Poll Interval command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.setPollInterval', async () => {
            await setPollInterval();
        })
    );

    // Toggle Enabled command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.toggleEnabled', async () => {
            await toggleEnabled();
        })
    );

    // Toggle Dev Dependencies command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.toggleDevDependencies', async () => {
            await toggleDevDependencies();
        })
    );

    // Show Output command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.showOutput', () => {
            logger.show();
        })
    );

    // Clear Diagnostics command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.clearDiagnostics', () => {
            diagnostics.clearAll();
            notifications.showSuccess('Cleared all diagnostics');
        })
    );

    // Set Log Level command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.setLogLevel', async () => {
            await setLogLevel();
        })
    );

    // See Current Violations command
    context.subscriptions.push(
        vscode.commands.registerCommand('repogate.seeViolations', async () => {
            await seeCurrentViolations();
        })
    );

    logger.info('Commands registered');
}

/**
 * Sign In with EntraID command implementation
 */
async function signInEntraID() {
    try {
        logger.info('=== Sign In with EntraID command triggered ===');
        logger.show(); // Show output panel for debugging
        statusBar.setStatus(RepoGateStatus.PENDING, 'Signing in...');
        
        const config = await authManager.authenticateWithEntraID();
        
        if (config && config.authMode === 'ENTRA_SSO') {
            const userInfo = await authManager.getUserInfo();
            if (userInfo) {
                statusBar.setUserInfo(userInfo.email, userInfo.authMode);
            }
            
            await updateAuthStatus();
            
            // Reset bootstrap state to force fresh scan on sign-in
            bootstrap.resetBootstrap();
            logger.info('Bootstrap state reset after sign-in');
            
            statusBar.setStatus(RepoGateStatus.CONNECTED, 'Connected');
            
            // Restart extension functionality
            await startWatchers(authManager['context']);
            
            // Prompt to reload window
            const result = await vscode.window.showInformationMessage(
                'Signed in successfully! Reload window to activate RepoGate?',
                'Reload Now',
                'Later'
            );
            
            if (result === 'Reload Now') {
                await vscode.commands.executeCommand('workbench.action.reloadWindow');
            }
        } else {
            statusBar.setStatus(RepoGateStatus.DISABLED, 'Not signed in');
            await updateAuthStatus();
        }
    } catch (error: any) {
        notifications.showError(`Sign in failed: ${error.message}`);
        statusBar.setStatus(RepoGateStatus.ERROR, 'Sign in failed');
        logger.error('Sign in error:', error);
    }
}

/**
 * Sign In with API Token command implementation
 */
async function signInAPIToken() {
    try {
        logger.info('=== Sign In with API Token command triggered ===');
        statusBar.setStatus(RepoGateStatus.PENDING, 'Signing in...');
        
        const config = await authManager.authenticateWithAPIToken();
        
        if (config && config.authMode === 'LOCAL_TOKEN') {
            const userInfo = await authManager.getUserInfo();
            if (userInfo) {
                statusBar.setUserInfo(userInfo.email, userInfo.authMode);
            }
            
            await updateAuthStatus();
            
            // Reset bootstrap state to force fresh scan on sign-in
            bootstrap.resetBootstrap();
            logger.info('Bootstrap state reset after sign-in');
            
            statusBar.setStatus(RepoGateStatus.CONNECTED, 'Connected');
            
            // Restart extension functionality
            await startWatchers(authManager['context']);
            
            // Prompt to reload window
            const result = await vscode.window.showInformationMessage(
                'Signed in successfully! Reload window to activate RepoGate?',
                'Reload Now',
                'Later'
            );
            
            if (result === 'Reload Now') {
                await vscode.commands.executeCommand('workbench.action.reloadWindow');
            }
        } else {
            statusBar.setStatus(RepoGateStatus.DISABLED, 'Not signed in');
            await updateAuthStatus();
        }
    } catch (error: any) {
        notifications.showError(`Sign in failed: ${error.message}`);
        statusBar.setStatus(RepoGateStatus.ERROR, 'Sign in failed');
        logger.error('Sign in error:', error);
    }
}

/**
 * Sign Out command implementation
 */
async function signOut() {
    try {
        const result = await vscode.window.showWarningMessage(
            'Are you sure you want to sign out? The extension will stop monitoring dependencies.',
            { modal: true },
            'Sign Out',
            'Cancel'
        );

        if (result === 'Sign Out') {
            // Stop watchers
            npmWatcher?.dispose();
            mavenWatcher?.dispose();
            gradleWatcher?.dispose();
            
            // Clear authentication
            await authManager.signOut();
            
            await updateAuthStatus();
            statusBar.setStatus(RepoGateStatus.DISABLED, 'Signed out');
            notifications.showSuccess('Signed out successfully');
            logger.info('User signed out');
        }
    } catch (error: any) {
        notifications.showError(`Sign out failed: ${error.message}`);
        logger.error('Sign out error:', error);
    }
}

/**
 * Show Account Info command implementation
 */
async function showAccountInfo() {
    try {
        const userInfo = await authManager.getUserInfo();
        
        if (!userInfo) {
            vscode.window.showInformationMessage('Not signed in');
            return;
        }

        const authMethodLabel = userInfo.authMode === 'ENTRA_SSO' ? 'EntraID SSO' : 'API Token (Legacy)';
        
        const message = `**Account Information**\n\n` +
            `**Name:** ${userInfo.name || 'N/A'}\n` +
            `**Email:** ${userInfo.email}\n` +
            `**User ID:** ${userInfo.id}\n` +
            `**Organization ID:** ${userInfo.orgId}\n` +
            `**Authentication Method:** ${authMethodLabel}`;
        
        vscode.window.showInformationMessage(message, { modal: true });
    } catch (error: any) {
        notifications.showError(`Failed to retrieve account info: ${error.message}`);
        logger.error('Show account info error:', error);
    }
}

/**
 * Update authentication status in settings
 */
async function updateAuthStatus() {
    const config = vscode.workspace.getConfiguration('repogate');
    const userInfo = await authManager.getUserInfo();
    
    let status: string;
    if (userInfo) {
        if (userInfo.authMode === 'ENTRA_SSO') {
            status = `✅ Signed in as ${userInfo.email} (EntraID SSO)`;
        } else {
            // API Token (Legacy) - no email stored
            status = `✅ Signed in with API Token (Legacy)`;
        }
    } else {
        status = '❌ Not signed in';
    }
    
    await config.update('authenticationStatus', status, vscode.ConfigurationTarget.Global);
}

/**
 * Set Token command implementation (legacy)
 */
async function setToken() {
    try {
        const token = await vscode.window.showInputBox({
            prompt: 'Enter your RepoGate API token',
            password: true,
            placeHolder: 'ghp_...',
            ignoreFocusOut: true,
            validateInput: (value) => {
                if (!value || value.trim() === '') {
                    return 'Token cannot be empty';
                }
                return null;
            }
        });

        if (token) {
            await authManager.setToken(token);
            await updateAuthStatus();
            notifications.showSuccess('API token saved securely');
            logger.info('API token updated');
            
            // Prompt to test connection
            const result = await vscode.window.showInformationMessage(
                'Token saved! Would you like to test the connection?',
                'Test Now',
                'Later'
            );
            
            if (result === 'Test Now') {
                await testConnection();
            }
        }
    } catch (error) {
        notifications.showError(`Failed to save token: ${error}`);
        logger.error('Set token error:', error);
    }
}

/**
 * Clear Token command implementation (legacy)
 */
async function clearToken() {
    try {
        const result = await vscode.window.showWarningMessage(
            'Are you sure you want to clear your API token? The extension will stop monitoring dependencies.',
            { modal: true },
            'Clear Token',
            'Cancel'
        );

        if (result === 'Clear Token') {
            await authManager.clearToken();
            await updateAuthStatus();
            statusBar.setStatus(RepoGateStatus.DISABLED, 'Not signed in');
            notifications.showSuccess('API token cleared');
            logger.info('API token cleared');
        }
    } catch (error) {
        notifications.showError(`Failed to clear token: ${error}`);
        logger.error('Clear token error:', error);
    }
}

/**
 * Test Connection command implementation
 */
async function testConnection() {
    try {
        statusBar.setStatus(RepoGateStatus.PENDING, 'Testing connection...');
        
        const config = await authManager.getConfig();
        if (!config || config.authMode === 'UNAUTHENTICATED') {
            notifications.showError('Not signed in. Please sign in first.');
            statusBar.setStatus(RepoGateStatus.ERROR, 'Not signed in');
            return;
        }

        const client = new RepoGateApiClient(config.apiUrl, authManager);
        const result = await client.testConnection();

        if (result.success) {
            notifications.showSuccess(`Connection successful!\n\nAPI URL: ${config.apiUrl}\nStatus: Connected`);
            statusBar.setStatus(RepoGateStatus.CONNECTED, 'Connected');
            logger.info('Connection test successful');
        } else {
            notifications.showError(`Connection failed!\n\n${result.message}\n\nPlease verify:\n1. RepoGate service is running\n2. API URL is correct\n3. You are signed in`);
            statusBar.setStatus(RepoGateStatus.ERROR, 'Connection failed');
            logger.error(`Connection test failed: ${result.message}`);
        }
    } catch (error) {
        notifications.showError(`Connection test failed: ${error}`);
        statusBar.setStatus(RepoGateStatus.ERROR, 'Connection failed');
        logger.error('Connection test error:', error);
    }
}

/**
 * Scan Now command implementation
 */
async function scanNow() {
    try {
        statusBar.setStatus(RepoGateStatus.PENDING, 'Scanning...');
        
        const config = await authManager.getConfig();
        if (!config || config.authMode === 'UNAUTHENTICATED') {
            notifications.showError('Not signed in. Please sign in first.');
            statusBar.setStatus(RepoGateStatus.ERROR, 'Not signed in');
            return;
        }

        // Reset bootstrap state to force re-scan
        bootstrap.resetBootstrap();
        
        const success = await bootstrap.bootstrapQueue(config);
        
        if (success) {
            statusBar.setStatus(RepoGateStatus.CONNECTED, 'Scan complete');
            notifications.showSuccess('Scan completed successfully');
            logger.info('Manual scan completed successfully');
        } else {
            statusBar.setStatus(RepoGateStatus.ERROR, 'Scan failed');
            notifications.showError('Scan failed. Please check the output for details.');
            logger.error('Manual scan failed');
        }
    } catch (error) {
        notifications.showError(`Scan failed: ${error}`);
        statusBar.setStatus(RepoGateStatus.ERROR, 'Scan failed');
        logger.error('Scan error:', error);
    }
}

/**
 * Set API URL command implementation
 */
async function setApiUrl() {
    try {
        const config = vscode.workspace.getConfiguration('repogate');
        const currentUrl = config.get<string>('apiUrl') || 'https://app.repogate.io/api/v1';

        const url = await vscode.window.showInputBox({
            prompt: 'Enter the RepoGate API URL',
            value: currentUrl,
            placeHolder: 'https://app.repogate.io/api/v1',
            ignoreFocusOut: true,
            validateInput: (value) => {
                if (!value || value.trim() === '') {
                    return 'API URL cannot be empty';
                }
                try {
                    new URL(value);
                    return null;
                } catch {
                    return 'Please enter a valid URL';
                }
            }
        });

        if (url) {
            await config.update('apiUrl', url, vscode.ConfigurationTarget.Global);
            notifications.showSuccess(`API URL updated to: ${url}`);
            logger.info(`API URL updated to: ${url}`);

            // Prompt to test connection
            const result = await vscode.window.showInformationMessage(
                'API URL updated! Would you like to test the connection?',
                'Test Now',
                'Later'
            );
            
            if (result === 'Test Now') {
                await testConnection();
            }
        }
    } catch (error) {
        notifications.showError(`Failed to update API URL: ${error}`);
        logger.error('Set API URL error:', error);
    }
}

/**
 * Set Poll Interval command implementation
 */
async function setPollInterval() {
    try {
        const config = vscode.workspace.getConfiguration('repogate');
        const currentInterval = config.get<number>('pollIntervalMs') || 10000;

        const input = await vscode.window.showInputBox({
            prompt: 'Enter the polling interval in milliseconds (minimum 3000ms)',
            value: currentInterval.toString(),
            placeHolder: '10000',
            ignoreFocusOut: true,
            validateInput: (value) => {
                const num = parseInt(value);
                if (isNaN(num)) {
                    return 'Please enter a valid number';
                }
                if (num < 3000) {
                    return 'Minimum interval is 3000ms (3 seconds)';
                }
                return null;
            }
        });

        if (input) {
            const interval = parseInt(input);
            await config.update('pollIntervalMs', interval, vscode.ConfigurationTarget.Global);
            notifications.showSuccess(`Poll interval updated to: ${interval}ms (${interval / 1000}s)`);
            logger.info(`Poll interval updated to: ${interval}ms`);
        }
    } catch (error) {
        notifications.showError(`Failed to update poll interval: ${error}`);
        logger.error('Set poll interval error:', error);
    }
}

/**
 * Toggle Enabled command implementation
 */
async function toggleEnabled() {
    try {
        const config = vscode.workspace.getConfiguration('repogate');
        const currentEnabled = config.get<boolean>('enabled', true);
        const newEnabled = !currentEnabled;

        await config.update('enabled', newEnabled, vscode.ConfigurationTarget.Global);
        
        if (newEnabled) {
            notifications.showSuccess('RepoGate enabled. Please reload the window to activate.');
            logger.info('RepoGate enabled');
            
            const result = await vscode.window.showInformationMessage(
                'RepoGate has been enabled. Reload the window to activate?',
                'Reload Now',
                'Later'
            );
            
            if (result === 'Reload Now') {
                await vscode.commands.executeCommand('workbench.action.reloadWindow');
            }
        } else {
            notifications.showSuccess('RepoGate disabled. Please reload the window to deactivate.');
            logger.info('RepoGate disabled');
            
            const result = await vscode.window.showInformationMessage(
                'RepoGate has been disabled. Reload the window to deactivate?',
                'Reload Now',
                'Later'
            );
            
            if (result === 'Reload Now') {
                await vscode.commands.executeCommand('workbench.action.reloadWindow');
            }
        }
    } catch (error) {
        notifications.showError(`Failed to toggle enabled state: ${error}`);
        logger.error('Toggle enabled error:', error);
    }
}

/**
 * Toggle Dev Dependencies command implementation
 */
async function toggleDevDependencies() {
    try {
        const config = vscode.workspace.getConfiguration('repogate');
        const currentInclude = config.get<boolean>('includeDevDependencies', true);
        const newInclude = !currentInclude;

        await config.update('includeDevDependencies', newInclude, vscode.ConfigurationTarget.Global);
        
        const status = newInclude ? 'enabled' : 'disabled';
        notifications.showSuccess(`Dev dependencies ${status} for scanning`);
        logger.info(`Include dev dependencies: ${newInclude}`);
    } catch (error) {
        notifications.showError(`Failed to toggle dev dependencies: ${error}`);
        logger.error('Toggle dev dependencies error:', error);
    }
}

/**
 * Set Log Level command implementation
 */
async function setLogLevel() {
    try {
        const currentLevel = vscode.workspace.getConfiguration('repogate').get<string>('logLevel', 'error');
        
        const level = await vscode.window.showQuickPick(
            [
                { label: 'Error', description: 'Only errors (recommended)', value: 'error' },
                { label: 'Warn', description: 'Errors and warnings', value: 'warn' },
                { label: 'Info', description: 'Errors, warnings, and info messages', value: 'info' },
                { label: 'Debug', description: 'All messages including debug', value: 'debug' }
            ],
            {
                placeHolder: `Current: ${currentLevel.toUpperCase()}`,
                title: 'Select Log Level'
            }
        );

        if (level) {
            const config = vscode.workspace.getConfiguration('repogate');
            await config.update('logLevel', level.value, vscode.ConfigurationTarget.Global);
            logger.setLogLevel(level.value);
            notifications.showSuccess(`Log level set to: ${level.label}`);
        }
    } catch (error) {
        notifications.showError(`Failed to set log level: ${error}`);
        logger.error('Set log level error:', error);
    }
}

/**
 * See Current Violations command implementation
 */
async function seeCurrentViolations() {
    try {
        const allDiagnostics = diagnostics.getAll();
        
        // Filter for denied packages only
        const violations: Array<{ project: string; package: string; message: string }> = [];
        
        for (const [uri, diags] of allDiagnostics) {
            const projectName = vscode.workspace.getWorkspaceFolder(uri)?.name || 'Unknown Project';
            
            for (const diag of diags) {
                if (diag.status === 'denied') {
                    violations.push({
                        project: projectName,
                        package: diag.packageName,
                        message: diag.message
                    });
                }
            }
        }

        if (violations.length === 0) {
            vscode.window.showInformationMessage('No violations found! All packages are compliant. ✅');
            return;
        }

        // Show violations in a modal
        const violationList = violations.map((v, i) => 
            `${i + 1}. ${v.project} - ${v.package}\n   ${v.message}`
        ).join('\n\n');

        const action = await vscode.window.showWarningMessage(
            `Found ${violations.length} violation(s)`,
            {
                modal: true,
                detail: violationList
            },
            'View in Problems Panel',
            'Dismiss'
        );

        if (action === 'View in Problems Panel') {
            vscode.commands.executeCommand('workbench.actions.view.problems');
        }
    } catch (error) {
        notifications.showError(`Failed to retrieve violations: ${error}`);
        logger.error('See violations error:', error);
    }
}

/**
 * Update status bar with diagnostic counts
 */
function updateStatusBarCounts() {
    setInterval(() => {
        const counts = diagnostics.getCounts();
        statusBar.setPendingCount(counts.pending + counts.scanning);
        statusBar.setDeniedCount(counts.denied);
    }, 2000);
}

export function deactivate() {
    logger.info('RepoGate extension deactivating...');
    
    heartbeat?.stop();
    npmWatcher?.dispose();
    mavenWatcher?.dispose();
    gradleWatcher?.dispose();
    statusBar.dispose();
    diagnostics.dispose();
    authManager.dispose();
    logger.dispose();
    
    logger.info('RepoGate extension deactivated');
}
