import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { logger } from '../utils/logger';

export class OAuthService {
    private codeVerifier?: string;
    private callbackDisposable?: vscode.Disposable;

    constructor(private context: vscode.ExtensionContext) {}

    /**
     * Start OAuth authentication flow
     * Returns tokens on success, undefined on failure/cancellation
     */
    async authenticate(tenantId: string, clientId: string, redirectUri: string): Promise<{ accessToken: string; refreshToken?: string } | undefined> {
        try {
            logger.info('=== Starting EntraID OAuth authentication flow ===');
            logger.info(`Tenant ID: ${tenantId}`);
            logger.info(`Client ID: ${clientId}`);
            logger.info(`Redirect URI: ${redirectUri}`);

            // Generate PKCE challenge
            const { codeVerifier, codeChallenge } = this.generatePKCE();
            this.codeVerifier = codeVerifier;

            // Build state parameter
            const state = this.buildState(clientId, codeVerifier, tenantId);

            // Build authorization URL
            const authUrl = this.buildAuthUrl(tenantId, clientId, redirectUri, codeChallenge, state);

            logger.info('Opening browser for EntraID authentication');

            // Register URI handler for callback
            const tokenPromise = this.listenForCallback();

            // Open browser
            logger.info('Opening browser with auth URL...');
            logger.info(`Auth URL: ${authUrl}`);
            const opened = await vscode.env.openExternal(vscode.Uri.parse(authUrl));
            if (!opened) {
                logger.error('Failed to open browser for authentication');
                vscode.window.showErrorMessage('Failed to open browser for authentication');
                return undefined;
            }
            logger.info('Browser opened successfully');

            vscode.window.showInformationMessage('Please complete sign-in in your browser...');

            // Wait for callback (with 5 minute timeout)
            const token = await Promise.race([
                tokenPromise,
                this.timeout(300000)
            ]);

            if (!token) {
                logger.warn('Authentication timed out or was cancelled');
                vscode.window.showWarningMessage('Authentication timed out or was cancelled');
            }

            return token;
        } catch (error: any) {
            logger.error('OAuth authentication error:', error);
            vscode.window.showErrorMessage(`Authentication failed: ${error.message}`);
            return undefined;
        } finally {
            // Clean up callback listener
            if (this.callbackDisposable) {
                this.callbackDisposable.dispose();
                this.callbackDisposable = undefined;
            }
        }
    }

    /**
     * Generate PKCE code verifier and challenge
     */
    private generatePKCE(): { codeVerifier: string; codeChallenge: string } {
        // Generate random code verifier (128 characters)
        const codeVerifier = this.base64URLEncode(crypto.randomBytes(96));

        // Generate SHA256 hash of verifier
        const hash = crypto.createHash('sha256').update(codeVerifier).digest();
        const codeChallenge = this.base64URLEncode(hash);

        logger.info('PKCE challenge generated');
        return { codeVerifier, codeChallenge };
    }

    /**
     * Base64 URL encode (without padding)
     */
    private base64URLEncode(buffer: Buffer): string {
        return buffer
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    /**
     * Build state parameter
     */
    private buildState(clientId: string, codeVerifier: string, tenantId: string): string {
        const stateObj = {
            clientType: 'vscode',
            codeVerifier,
            tenantId
        };
        return Buffer.from(JSON.stringify(stateObj)).toString('base64');
    }

    /**
     * Build OAuth authorization URL
     */
    private buildAuthUrl(
        tenantId: string,
        clientId: string,
        redirectUri: string,
        codeChallenge: string,
        state: string
    ): string {
        const params = new URLSearchParams({
            client_id: clientId,
            response_type: 'code',
            redirect_uri: redirectUri,
            response_mode: 'query',
            scope: 'openid profile email offline_access',  // Added offline_access for refresh tokens
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });

        const authUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?${params.toString()}`;
        logger.info('OAuth authorization URL built');
        return authUrl;
    }

    /**
     * Listen for OAuth callback
     */
    private async listenForCallback(): Promise<{ accessToken: string; refreshToken?: string } | undefined> {
        return new Promise((resolve) => {
            // Register URI handler
            this.callbackDisposable = vscode.window.registerUriHandler({
                handleUri: async (uri: vscode.Uri) => {
                    logger.info(`OAuth callback received: ${uri.path}`);
                    logger.info(`Full URI: ${uri.toString()}`);
                    
                    // Check if this is the auth callback
                    if (uri.path.includes('/auth-callback') || uri.path.includes('/auth/entra/success')) {
                        // Decode the query string first (backend may double-encode)
                        const decodedQuery = decodeURIComponent(uri.query);
                        logger.info(`Decoded query: ${decodedQuery}`);
                        
                        const params = new URLSearchParams(decodedQuery);
                        const token = params.get('token');
                        const refreshToken = params.get('refreshToken');
                        
                        if (token) {
                            logger.info('Entra ID token extracted from callback');
                            logger.info(`Token length: ${token.length}`);
                            if (refreshToken) {
                                logger.info('Refresh token extracted from callback');
                                logger.info(`Refresh token length: ${refreshToken.length}`);
                            } else {
                                logger.warn('No refresh token in callback URL');
                            }
                            resolve({ accessToken: token, refreshToken: refreshToken || undefined });
                        } else {
                            logger.error('No token in callback URL');
                            logger.error(`Raw query: ${uri.query}`);
                            logger.error(`Decoded query: ${decodedQuery}`);
                            vscode.window.showErrorMessage('Authentication failed: No token received');
                            resolve(undefined);
                        }
                    } else if (uri.path.includes('/auth/entra/error')) {
                        const error = new URLSearchParams(uri.query).get('error');
                        const message = new URLSearchParams(uri.query).get('message');
                        logger.error(`OAuth error: ${error} - ${message}`);
                        vscode.window.showErrorMessage(`Authentication failed: ${message || error}`);
                        resolve(undefined);
                    }
                }
            });

            // Store disposable for cleanup
            if (this.callbackDisposable) {
                this.context.subscriptions.push(this.callbackDisposable);
            }
        });
    }

    /**
     * Timeout promise helper
     */
    private timeout(ms: number): Promise<undefined> {
        return new Promise((resolve) => {
            setTimeout(() => {
                logger.warn('OAuth authentication timed out');
                resolve(undefined);
            }, ms);
        });
    }

    /**
     * Dispose resources
     */
    dispose(): void {
        if (this.callbackDisposable) {
            this.callbackDisposable.dispose();
            this.callbackDisposable = undefined;
        }
    }
}
