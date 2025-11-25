import axios, { AxiosInstance, AxiosError, InternalAxiosRequestConfig } from 'axios';
import { logger } from '../utils/logger';
import { AuthManager } from '../auth/authManager';

export interface QueueRequest {
    projectName: string;
    ecosystem: string;
    packages: Array<{
        name: string;
        version?: string;
        path: string;
    }>;
    timestamp: string;
    repository?: boolean;
}

export interface RequestPayload {
    projectName: string;
    ecosystem: string;
    name: string;
    version?: string;
    path: string;
    repository?: boolean;
}

export interface CheckPayload {
    projectName: string;
    ecosystem: string;
    name: string;
    version?: string;
    repository?: boolean;
}

export interface CheckResponse {
    status: 'approved' | 'denied' | 'pending' | 'scanning' | 'not_found';
    approved: boolean;
    message: string;
    packageName: string;
    packageManager: string;
    reasonUrl?: string;
}

export interface UpdatePayload {
    projectName: string;
    ecosystem: string;
    name: string;
    fromVersion?: string;
    toVersion?: string;
    action: string;
    timestamp: string;
    repository?: boolean;
}

export interface HeartbeatResponse {
    status: 'healthy' | 'warning';
    message: string;
    timestamp: string;
    deniedPackages?: string[];
    alert?: {
        severity: 'warning';
        title: string;
        message: string;
        packages: string[];
    };
}

export class RepoGateApiClient {
    private client: AxiosInstance;
    private maxRetries = 3;
    private baseDelay = 1000; // 1 second
    private isRefreshing = false;

    constructor(
        private baseURL: string,
        private authManager: AuthManager
    ) {
        this.client = axios.create({
            baseURL,
            timeout: 30000,
            headers: {
                'Content-Type': 'application/json'
            }
        });

        // Add request interceptor to inject token
        this.client.interceptors.request.use(
            async (config) => await this.injectToken(config),
            (error) => Promise.reject(error)
        );

        // Add response interceptor to handle 401 errors
        this.client.interceptors.response.use(
            (response) => response,
            async (error) => await this.handleResponseError(error)
        );
    }

    /**
     * Inject authentication token into request
     */
    private async injectToken(config: InternalAxiosRequestConfig): Promise<InternalAxiosRequestConfig> {
        const authConfig = await this.authManager.getConfig();

        if (authConfig.authMode === 'ENTRA_SSO' && authConfig.accessToken) {
            config.headers.Authorization = `Bearer ${authConfig.accessToken}`;
        } else if (authConfig.authMode === 'LOCAL_TOKEN' && authConfig.apiToken) {
            config.headers.Authorization = `Bearer ${authConfig.apiToken}`;
        }

        return config;
    }

    /**
     * Handle response errors, including token refresh on 401
     */
    private async handleResponseError(error: AxiosError): Promise<any> {
        const originalRequest = error.config;

        // Handle 401 Unauthorized
        if (error.response?.status === 401 && originalRequest && !this.isRefreshing) {
            const authConfig = await this.authManager.getConfig();

            // Only attempt refresh for ENTRA_SSO users
            if (authConfig.authMode === 'ENTRA_SSO') {
                this.isRefreshing = true;
                
                try {
                    logger.info('401 error, attempting token refresh');
                    const refreshed = await this.authManager.refreshToken();
                    
                    if (refreshed) {
                        logger.info('Token refreshed successfully, retrying request');
                        this.isRefreshing = false;
                        
                        // Retry the original request with new token
                        return this.client.request(originalRequest);
                    } else {
                        logger.warn('Token refresh failed, clearing auth state');
                        // Clear expired/invalid auth state
                        await this.authManager.signOut();
                        throw new Error('Authentication expired. Please sign in again.');
                    }
                } catch (refreshError) {
                    logger.error('Token refresh error:', refreshError);
                    this.isRefreshing = false;
                    throw refreshError;
                } finally {
                    this.isRefreshing = false;
                }
            } else {
                // For LOCAL_TOKEN or unauthenticated, just reject
                logger.error('401 error with non-refreshable auth mode');
            }
        }

        return Promise.reject(error);
    }

    /**
     * POST /queue - Submit initial inventory
     */
    async queue(payload: QueueRequest): Promise<void> {
        await this.retryRequest(async () => {
            logger.info(`Queuing ${payload.packages.length} packages for ${payload.ecosystem}`);
            await this.client.post('/queue', payload);
            logger.info(`Successfully queued packages`);
        });
    }

    /**
     * POST /dependencies/request - Request approval for new dependency
     */
    async request(payload: RequestPayload): Promise<CheckResponse> {
        return await this.retryRequest(async () => {
            logger.info(`Requesting approval for ${payload.name}@${payload.version || 'latest'}`);
            const response = await this.client.post('/dependencies/request', payload);
            return response.data;
        });
    }

    /**
     * POST /dependencies/check - Check approval status
     */
    async check(payload: CheckPayload): Promise<CheckResponse> {
        return await this.retryRequest(async () => {
            const response = await this.client.post('/dependencies/check', {
                packageName: payload.name,
                packageManager: payload.ecosystem,
                packageVersion: payload.version
            });
            return response.data;
        });
    }

    /**
     * POST /dependencies/update - Notify of dependency changes
     */
    async update(payload: UpdatePayload): Promise<void> {
        await this.retryRequest(async () => {
            logger.info(`Updating dependency status: ${payload.name} (${payload.action})`);
            await this.client.post('/dependencies/update', payload);
        });
    }

    /**
     * POST /heartbeat - Send heartbeat and receive denied package notifications
     */
    async heartbeat(): Promise<HeartbeatResponse> {
        return await this.retryRequest(async () => {
            const response = await this.client.post('/heartbeat', {});
            return response.data;
        });
    }

    /**
     * Test connection to API
     */
    async testConnection(): Promise<{ success: boolean; message: string }> {
        try {
            await this.client.post('/dependencies/check', {
                packageName: 'test-package',
                packageManager: 'npm'
            });
            return {
                success: true,
                message: 'Connection successful'
            };
        } catch (error) {
            const axiosError = error as AxiosError;
            if (axiosError.response?.status === 401) {
                return {
                    success: false,
                    message: 'Authentication failed: Invalid credentials'
                };
            } else if (axiosError.code === 'ECONNREFUSED') {
                return {
                    success: false,
                    message: 'Cannot connect to server: Connection refused'
                };
            } else {
                return {
                    success: false,
                    message: `Connection failed: ${axiosError.message}`
                };
            }
        }
    }

    /**
     * Retry logic with exponential backoff
     */
    private async retryRequest<T>(
        fn: () => Promise<T>,
        attempt: number = 0
    ): Promise<T> {
        try {
            return await fn();
        } catch (error) {
            const axiosError = error as AxiosError;
            
            // Don't retry on 4xx errors (client errors)
            if (axiosError.response && axiosError.response.status >= 400 && axiosError.response.status < 500) {
                logger.error(`Client error (${axiosError.response.status}): ${axiosError.message}`);
                throw error;
            }

            // Retry on 5xx errors or network errors
            if (attempt < this.maxRetries) {
                const delay = this.baseDelay * Math.pow(2, attempt) + Math.random() * 1000; // Add jitter
                logger.warn(`Request failed, retrying in ${Math.round(delay)}ms (attempt ${attempt + 1}/${this.maxRetries})`);
                await this.sleep(delay);
                return this.retryRequest(fn, attempt + 1);
            }

            logger.error(`Request failed after ${this.maxRetries} retries: ${axiosError.message}`);
            throw error;
        }
    }

    private sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}
