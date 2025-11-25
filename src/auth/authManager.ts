import * as vscode from 'vscode';
import axios from 'axios';
import { OAuthService } from './oauthService';
import { logger } from '../utils/logger';

export interface RepoGateConfig {
    apiUrl: string;
    apiToken?: string;  // Optional - only for LOCAL_TOKEN users
    accessToken?: string;  // Optional - JWT for ENTRA_SSO users
    authMode: 'LOCAL_TOKEN' | 'ENTRA_SSO' | 'UNAUTHENTICATED';
    pollIntervalMs: number;
    includeDevDependencies: boolean;
    userEmail?: string;
    userName?: string;
    userId?: string;
    orgId?: string;
    tokenExpiration?: number;  // Unix timestamp
}

export interface AuthModeResponse {
    authMode: 'ENTRA_SSO' | 'LOCAL_TOKEN';
    organizationName: string;
    requiresEntraSso: boolean;
    tenantId?: string;
    clientId?: string;
    redirectUri?: string;
}

export interface EntraAuthResponse {
    accessToken: string;
    tokenType: string;
    expiresIn: number;
    user: {
        id: string;
        email: string;
        name: string;
        orgId: string;
        authMode: string;
    };
}

export interface TokenRefreshResponse {
    accessToken: string;
    tokenType: string;
    expiresIn: number;
}

export interface UserInfo {
    id: string;
    email: string;
    name: string;
    orgId: string;
    authMode: 'LOCAL_TOKEN' | 'ENTRA_SSO';
}

const TOKEN_KEY = 'repogate.apiToken';
const ACCESS_TOKEN_KEY = 'repogate.accessToken';
const REFRESH_TOKEN_KEY = 'repogate.refreshToken';

export class AuthManager {
    private oauthService: OAuthService;
    private refreshTimer?: NodeJS.Timeout;

    constructor(private context: vscode.ExtensionContext) {
        this.oauthService = new OAuthService(context);
    }

    /**
     * Ensure authentication is configured, prompt if missing
     * Returns config if ready, undefined if not
     */
    async ensureAuthOrPrompt(): Promise<RepoGateConfig | undefined> {
        // Check if already authenticated
        const existingConfig = await this.getConfig();
        if (existingConfig && existingConfig.authMode !== 'UNAUTHENTICATED') {
            // Verify token is still valid
            if (await this.isTokenValid(existingConfig)) {
                // Restart timer if using Entra SSO
                if (existingConfig.authMode === 'ENTRA_SSO' && existingConfig.tokenExpiration) {
                    const timeUntilExpiration = existingConfig.tokenExpiration - Date.now();
                    const expiresIn = Math.max(Math.floor(timeUntilExpiration / 1000), 0);
                    this.startTokenRefreshTimer(expiresIn);
                    logger.info(`Token refresh timer restarted (expires in ${expiresIn}s)`);
                }
                return existingConfig;
            }
            
            // Try to refresh expired token on startup
            if (existingConfig.authMode === 'ENTRA_SSO') {
                logger.info('Token expired on startup, attempting refresh...');
                const refreshed = await this.refreshToken();
                if (refreshed) {
                    return await this.getConfig();
                }
            }
        }

        // Not authenticated, prompt user
        await this.promptForAuth();
        return undefined;
    }

    /**
     * Prompt user to authenticate
     */
    private async promptForAuth(): Promise<void> {
        const result = await vscode.window.showInformationMessage(
            'RepoGate: Please sign in to use this extension.',
            'Sign In with EntraID',
            'Sign In with API Token (Legacy)',
            'Get Help'
        );

        if (result === 'Sign In with EntraID') {
            await vscode.commands.executeCommand('repogate.signInEntraID');
        } else if (result === 'Sign In with API Token (Legacy)') {
            await vscode.commands.executeCommand('repogate.signInAPIToken');
        } else if (result === 'Get Help') {
            vscode.env.openExternal(vscode.Uri.parse('https://repogate.io/docs/getting-started'));
        }
    }

    /**
     * Initiate EntraID authentication flow
     */
    async authenticateWithEntraID(email?: string): Promise<RepoGateConfig | undefined> {
        try {
            // Prompt for email if not provided
            if (!email) {
                email = await this.promptForEmail();
                if (!email) {
                    return undefined;
                }
            }

            // Discover auth mode
            const authModeResponse = await this.discoverAuthMode(email);
            if (!authModeResponse) {
                return undefined;
            }

            // Check if EntraID is required
            if (authModeResponse.authMode !== 'ENTRA_SSO') {
                vscode.window.showWarningMessage(
                    `Your organization (${authModeResponse.organizationName}) uses API Token authentication. Please use "Sign In with API Token (Legacy)" instead.`
                );
                return undefined;
            }

            logger.info('Starting EntraID authentication flow');

            // Start OAuth flow
            const tokens = await this.oauthService.authenticate(
                authModeResponse.tenantId!,
                authModeResponse.clientId!,
                authModeResponse.redirectUri!
            );

            if (!tokens) {
                logger.warn('EntraID authentication cancelled or failed');
                return undefined;
            }

            // Store refresh token if available
            if (tokens.refreshToken) {
                await this.context.secrets.store(REFRESH_TOKEN_KEY, tokens.refreshToken);
                logger.info('Refresh token stored from OAuth callback');
            } else {
                logger.warn('No refresh token received from OAuth callback');
            }

            // Exchange Entra token for RepoGate JWT
            const authResponse = await this.exchangeEntraToken(tokens.accessToken);
            if (!authResponse) {
                return undefined;
            }

            // Store authentication data
            await this.storeEntraAuth(authResponse);

            // Start token refresh timer
            this.startTokenRefreshTimer(authResponse.expiresIn);

            logger.info('EntraID authentication successful');
            vscode.window.showInformationMessage(`Signed in as ${authResponse.user.name} (${authResponse.user.email})`);
            
            return await this.getConfig();
        } catch (error: any) {
            logger.error('EntraID authentication failed:', error);
            vscode.window.showErrorMessage(`Authentication failed: ${error.message}`);
            return undefined;
        }
    }

    /**
     * Initiate API Token authentication flow
     */
    async authenticateWithAPIToken(): Promise<RepoGateConfig | undefined> {
        try {
            logger.info('Starting API Token authentication flow');

            // Prompt for API token directly (no email or auth mode check)
            const token = await vscode.window.showInputBox({
                prompt: 'Enter your RepoGate API token',
                password: true,
                placeHolder: 'rg_...',
                ignoreFocusOut: true,
                validateInput: (value) => {
                    if (!value || value.trim() === '') {
                        return 'Token cannot be empty';
                    }
                    return null;
                }
            });

            if (!token) {
                return undefined;
            }

            // Store token
            await this.context.secrets.store(TOKEN_KEY, token);
            await this.context.globalState.update('authMode', 'LOCAL_TOKEN');

            logger.info('API token stored successfully');
            vscode.window.showInformationMessage('API Token saved successfully');
            
            return await this.getConfig();
        } catch (error: any) {
            logger.error('API token authentication failed:', error);
            vscode.window.showErrorMessage(`Authentication failed: ${error.message}`);
            return undefined;
        }
    }

    /**
     * Prompt user for email address
     */
    private async promptForEmail(): Promise<string | undefined> {
        const email = await vscode.window.showInputBox({
            prompt: 'Enter your email address to sign in to RepoGate',
            placeHolder: 'user@example.com',
            ignoreFocusOut: true,
            validateInput: (value) => {
                if (!value || value.trim() === '') {
                    return 'Email address is required';
                }
                // Basic email validation
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(value)) {
                    return 'Please enter a valid email address';
                }
                return null;
            }
        });

        return email?.trim();
    }

    /**
     * Discover authentication mode for email
     */
    private async discoverAuthMode(email: string): Promise<AuthModeResponse | undefined> {
        try {
            logger.info(`Discovering auth mode for ${email}`);
            const config = vscode.workspace.getConfiguration('repogate');
            const apiUrl = config.get<string>('apiUrl') || 'https://app.repogate.io/api/v1';

            const response = await axios.get<AuthModeResponse>(`${apiUrl}/auth/mode`, {
                params: { email }
            });

            logger.info(`Auth mode discovered: ${response.data.authMode} for ${response.data.organizationName}`);
            return response.data;
        } catch (error: any) {
            logger.error('Failed to discover auth mode:', error);
            vscode.window.showErrorMessage(
                `Failed to determine authentication method: ${error.response?.data?.message || error.message}`
            );
            return undefined;
        }
    }

    /**
     * Exchange Entra ID token for RepoGate JWT
     */
    private async exchangeEntraToken(entraToken: string): Promise<EntraAuthResponse | undefined> {
        try {
            const config = vscode.workspace.getConfiguration('repogate');
            const apiUrl = config.get<string>('apiUrl') || 'https://app.repogate.io/api/v1';

            const extensionVersion = vscode.extensions.getExtension('repogate.repogate')?.packageJSON.version || '1.0.0';

            const response = await axios.post<EntraAuthResponse>(
                `${apiUrl}/auth/entra/connect`,
                {
                    client: 'vscode',
                    extensionVersion: extensionVersion
                },
                {
                    headers: {
                        'Authorization': `Bearer ${entraToken}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            return response.data;
        } catch (error: any) {
            logger.error('Token exchange failed:', error);
            
            // Handle specific error codes
            if (error.response?.status === 403) {
                const errorCode = error.response.data?.error;
                this.handleAuthError(errorCode, error.response.data?.message);
            } else {
                vscode.window.showErrorMessage(`Token exchange failed: ${error.response?.data?.message || error.message}`);
            }
            
            return undefined;
        }
    }

    /**
     * Store EntraID authentication data
     */
    private async storeEntraAuth(authResponse: EntraAuthResponse): Promise<void> {
        // Store access token in SecretStorage
        await this.context.secrets.store(ACCESS_TOKEN_KEY, authResponse.accessToken);
        
        // Store refresh token if available
        if ((authResponse as any).refreshToken) {
            await this.context.secrets.store(REFRESH_TOKEN_KEY, (authResponse as any).refreshToken);
            logger.info('Refresh token stored successfully');
        }

        // Store user info and auth mode in GlobalState
        await this.context.globalState.update('userEmail', authResponse.user.email);
        await this.context.globalState.update('userName', authResponse.user.name);
        await this.context.globalState.update('userId', authResponse.user.id);
        await this.context.globalState.update('orgId', authResponse.user.orgId);
        await this.context.globalState.update('authMode', 'ENTRA_SSO');
        
        // Calculate and store expiration timestamp
        const expirationTime = Date.now() + (authResponse.expiresIn * 1000);
        await this.context.globalState.update('tokenExpiration', expirationTime);

        logger.info('EntraID auth data stored successfully');
    }

    /**
     * Refresh expired JWT token using refresh token
     */
    async refreshToken(): Promise<boolean> {
        try {
            const refreshToken = await this.context.secrets.get(REFRESH_TOKEN_KEY);
            if (!refreshToken) {
                logger.warn('No refresh token available');
                return false;
            }

            const config = vscode.workspace.getConfiguration('repogate');
            const apiUrl = config.get<string>('apiUrl') || 'https://app.repogate.io/api/v1';

            const accessToken = await this.context.secrets.get(ACCESS_TOKEN_KEY);
            
            logger.info('Refreshing access token using refresh token');
            const response = await axios.post<TokenRefreshResponse>(
                `${apiUrl}/auth/entra/refresh`,
                {
                    refreshToken: refreshToken  // Send refresh token in body
                },
                {
                    headers: {
                        'Authorization': `Bearer ${accessToken || ''}`  // Send expired access token for session ID
                    }
                }
            );

            // Store new access token
            await this.context.secrets.store(ACCESS_TOKEN_KEY, response.data.accessToken);
            
            // Store new refresh token if provided (token rotation)
            if ((response.data as any).refreshToken) {
                await this.context.secrets.store(REFRESH_TOKEN_KEY, (response.data as any).refreshToken);
                logger.info('New refresh token stored (token rotation)');
            }
            
            // Update expiration time
            const expirationTime = Date.now() + (response.data.expiresIn * 1000);
            await this.context.globalState.update('tokenExpiration', expirationTime);

            // Restart refresh timer
            this.startTokenRefreshTimer(response.data.expiresIn);

            logger.info('Token refreshed successfully');
            return true;
        } catch (error: any) {
            logger.error('Token refresh failed:', error);
            
            // Clear expired token and prompt for re-authentication
            await this.signOut();
            vscode.window.showWarningMessage(
                'Your session has expired. Please sign in again.',
                'Sign In'
            ).then(selection => {
                if (selection === 'Sign In') {
                    vscode.commands.executeCommand('repogate.signInEntraID');
                }
            });
            
            return false;
        }
    }

    /**
     * Start automatic token refresh timer
     */
    private startTokenRefreshTimer(expiresIn: number): void {
        // Clear existing timer
        if (this.refreshTimer) {
            clearTimeout(this.refreshTimer);
        }

        // Refresh 5 minutes before expiration
        const refreshDelay = Math.max((expiresIn - 300) * 1000, 60000); // At least 1 minute
        
        logger.info(`Token refresh scheduled in ${refreshDelay / 1000} seconds`);
        
        this.refreshTimer = setTimeout(async () => {
            logger.info('Automatic token refresh triggered');
            await this.refreshToken();
        }, refreshDelay);
    }

    /**
     * Check if token is valid
     */
    private async isTokenValid(config: RepoGateConfig): Promise<boolean> {
        if (config.authMode === 'LOCAL_TOKEN') {
            // API tokens don't expire (or we don't track expiration)
            return true;
        }

        if (config.authMode === 'ENTRA_SSO') {
            const expiration = config.tokenExpiration;
            if (!expiration) {
                return false;
            }

            // Check if token expires in less than 5 minutes
            const timeUntilExpiration = expiration - Date.now();
            if (timeUntilExpiration < 300000) { // 5 minutes
                logger.info('Token expiring soon, refreshing...');
                return await this.refreshToken();
            }

            return true;
        }

        return false;
    }

    /**
     * Sign out and clear all authentication data
     */
    async signOut(): Promise<void> {
        logger.info('Signing out');

        // Clear timers
        if (this.refreshTimer) {
            clearTimeout(this.refreshTimer);
            this.refreshTimer = undefined;
        }

        // Clear secrets
        await this.context.secrets.delete(TOKEN_KEY);
        await this.context.secrets.delete(ACCESS_TOKEN_KEY);
        await this.context.secrets.delete(REFRESH_TOKEN_KEY);

        // Clear global state
        await this.context.globalState.update('userEmail', undefined);
        await this.context.globalState.update('userName', undefined);
        await this.context.globalState.update('userId', undefined);
        await this.context.globalState.update('orgId', undefined);
        await this.context.globalState.update('authMode', undefined);
        await this.context.globalState.update('tokenExpiration', undefined);

        logger.info('Sign out complete');
    }

    /**
     * Get current token (API token or JWT)
     */
    async getToken(): Promise<string | undefined> {
        const authMode = this.context.globalState.get<'LOCAL_TOKEN' | 'ENTRA_SSO'>('authMode');
        
        if (authMode === 'LOCAL_TOKEN') {
            return await this.context.secrets.get(TOKEN_KEY);
        } else if (authMode === 'ENTRA_SSO') {
            return await this.context.secrets.get(ACCESS_TOKEN_KEY);
        }
        
        return undefined;
    }

    /**
     * Store token (for legacy API token flow)
     */
    async setToken(token: string): Promise<void> {
        await this.context.secrets.store(TOKEN_KEY, token);
    }

    /**
     * Clear token (for legacy API token flow)
     */
    async clearToken(): Promise<void> {
        await this.signOut();
    }

    /**
     * Get current configuration
     */
    async getConfig(): Promise<RepoGateConfig> {
        const config = vscode.workspace.getConfiguration('repogate');
        const apiUrl = config.get<string>('apiUrl') || 'https://app.repogate.io/api/v1';
        const pollIntervalMs = Math.max(config.get<number>('pollIntervalMs') || 10000, 3000);
        const includeDevDependencies = config.get<boolean>('includeDevDependencies') ?? true;

        const authMode = this.context.globalState.get<'LOCAL_TOKEN' | 'ENTRA_SSO'>('authMode') || 'UNAUTHENTICATED';
        const apiToken = await this.context.secrets.get(TOKEN_KEY);
        const accessToken = await this.context.secrets.get(ACCESS_TOKEN_KEY);

        return {
            apiUrl,
            apiToken,
            accessToken,
            authMode: authMode as any,
            pollIntervalMs,
            includeDevDependencies,
            userEmail: this.context.globalState.get<string>('userEmail'),
            userName: this.context.globalState.get<string>('userName'),
            userId: this.context.globalState.get<string>('userId'),
            orgId: this.context.globalState.get<string>('orgId'),
            tokenExpiration: this.context.globalState.get<number>('tokenExpiration')
        };
    }

    /**
     * Get user information
     */
    async getUserInfo(): Promise<UserInfo | undefined> {
        const authMode = this.context.globalState.get<'LOCAL_TOKEN' | 'ENTRA_SSO'>('authMode');
        if (!authMode) {
            return undefined;
        }

        return {
            id: this.context.globalState.get<string>('userId') || '',
            email: this.context.globalState.get<string>('userEmail') || '',
            name: this.context.globalState.get<string>('userName') || '',
            orgId: this.context.globalState.get<string>('orgId') || '',
            authMode
        };
    }

    /**
     * Handle authentication errors
     */
    private handleAuthError(errorCode: string, message: string): void {
        switch (errorCode) {
            case 'TenantMismatch':
                vscode.window.showErrorMessage(
                    'Authentication Error: Your account belongs to a different organization. Please contact your administrator.'
                );
                break;
            case 'USER_NOT_PROVISIONED':
                vscode.window.showErrorMessage(
                    'Your account needs to be added by your administrator. Please contact your RepoGate administrator to provision your account.'
                );
                break;
            case 'UserInactive':
                vscode.window.showErrorMessage(
                    'Your account has been disabled. Please contact your administrator.'
                );
                break;
            case 'AuthModeMismatch':
                vscode.window.showWarningMessage(
                    'Your organization uses API token authentication. Please use "Sign In with API Token (Legacy)" instead.'
                );
                break;
            case 'EntraSSODisabled':
                vscode.window.showErrorMessage(
                    'EntraID SSO is not enabled for your organization. Please contact your administrator.'
                );
                break;
            default:
                vscode.window.showErrorMessage(
                    `Authentication failed: ${message || 'Unknown error'}`
                );
        }
    }

    /**
     * Dispose resources
     */
    dispose(): void {
        if (this.refreshTimer) {
            clearTimeout(this.refreshTimer);
        }
        this.oauthService.dispose();
    }
}
