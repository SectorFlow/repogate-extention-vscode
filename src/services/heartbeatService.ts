import * as vscode from 'vscode';
import { RepoGateApiClient, HeartbeatResponse } from '../api/client';
import { AuthManager } from '../auth/authManager';
import { logger } from '../utils/logger';
import { NotificationManager } from '../ui/notifications/notificationManager';

export class HeartbeatService {
    private interval: NodeJS.Timeout | undefined;
    private readonly HEARTBEAT_INTERVAL_MS = 60000; // 1 minute
    private isRunning = false;
    private notifiedPackages: Set<string> = new Set(); // Track packages we've already notified about

    constructor(
        private context: vscode.ExtensionContext,
        private authManager: AuthManager,
        private notifications: NotificationManager
    ) {}

    /**
     * Start heartbeat service
     */
    async start(): Promise<void> {
        if (this.isRunning) {
            logger.warn('Heartbeat service is already running');
            return;
        }

        logger.info('Starting heartbeat service...');
        this.isRunning = true;

        // Send initial heartbeat immediately
        await this.sendHeartbeat();

        // Schedule periodic heartbeats
        this.interval = setInterval(async () => {
            await this.sendHeartbeat();
        }, this.HEARTBEAT_INTERVAL_MS);

        this.context.subscriptions.push({
            dispose: () => this.stop()
        });

        logger.info(`Heartbeat service started (interval: ${this.HEARTBEAT_INTERVAL_MS / 1000}s)`);
    }

    /**
     * Stop heartbeat service
     */
    stop(): void {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = undefined;
        }
        this.isRunning = false;
        logger.info('Heartbeat service stopped');
    }

    /**
     * Send heartbeat to server
     */
    private async sendHeartbeat(): Promise<void> {
        try {
            const config = await this.authManager.getConfig();
            if (!config || config.authMode === 'UNAUTHENTICATED') {
                logger.debug('Skipping heartbeat: not authenticated');
                return;
            }

            logger.debug(`Sending heartbeat to: ${config.apiUrl}/heartbeat`);
            const client = new RepoGateApiClient(config.apiUrl, this.authManager);
            const response = await client.heartbeat();

            logger.debug(`Heartbeat response received:`, JSON.stringify(response, null, 2));
            logger.debug(`Heartbeat status: ${response?.status}, message: ${response?.message}`);

            // Handle response
            if (response) {
                await this.handleHeartbeatResponse(response);
            } else {
                logger.warn('Heartbeat response is undefined - backend may not be returning proper response');
            }
        } catch (error) {
            logger.error('Heartbeat failed:', error);
            // Don't show error to user - heartbeat failures should be silent
        }
    }

    /**
     * Handle heartbeat response
     */
    private async handleHeartbeatResponse(response: HeartbeatResponse): Promise<void> {
        if (response.status === 'healthy') {
            // All good, nothing to do
            return;
        }

        if (response.status === 'warning' && response.alert) {
            // Denied packages detected
            await this.handleDeniedPackagesAlert(response.alert);
        }
    }

    /**
     * Handle denied packages alert
     */
    private async handleDeniedPackagesAlert(alert: {
        severity: 'warning';
        title: string;
        message: string;
        packages: string[];
        packageDetails?: Array<{
            name: string;
            version?: string;
            ecosystem: string;
            filePath?: string;
            reason: string;
        }>;
    }): Promise<void> {
        // Use detailed package info if available, otherwise fall back to simple names
        const packageDetails: Array<{
            name: string;
            version?: string;
            ecosystem: string;
            filePath?: string;
            reason: string;
        }> = alert.packageDetails || alert.packages.map(name => ({
            name,
            ecosystem: 'unknown',
            reason: 'Denied by security policy'
        }));

        // Filter out packages we've already notified about
        const newDeniedPackages = packageDetails.filter(pkg => !this.notifiedPackages.has(pkg.name));

        if (newDeniedPackages.length === 0) {
            logger.debug('No new denied packages to notify about');
            return;
        }

        // Mark these packages as notified
        newDeniedPackages.forEach(pkg => this.notifiedPackages.add(pkg.name));

        logger.warn(`Denied packages detected: ${newDeniedPackages.map(p => p.name).join(', ')}`);

        // Build detailed package list for display
        const packageList = newDeniedPackages.map(pkg => {
            const version = pkg.version ? `@${pkg.version}` : '';
            const location = pkg.filePath ? `\n  Location: ${pkg.filePath}` : '';
            const reason = pkg.reason ? `\n  Reason: ${pkg.reason}` : '';
            return `• ${pkg.name}${version} (${pkg.ecosystem})${location}${reason}`;
        }).join('\n\n');

        const fullMessage = `${alert.message}\n\n${packageList}`;

        const action = await vscode.window.showWarningMessage(
            alert.title,
            {
                modal: true,
                detail: fullMessage
            },
            'View Full Report',
            'Copy Details',
            'Dismiss'
        );

        if (action === 'View Full Report') {
            // Create a detailed report in the output panel
            logger.info('=== DENIED PACKAGES REPORT ===');
            logger.info(alert.message);
            logger.info('');
            logger.info(`Total denied packages: ${newDeniedPackages.length}`);
            logger.info('');
            
            newDeniedPackages.forEach((pkg, index) => {
                logger.info(`${index + 1}. ${pkg.name}${pkg.version ? '@' + pkg.version : ''}`);
                logger.info(`   Ecosystem: ${pkg.ecosystem}`);
                if (pkg.filePath) {
                    logger.info(`   Location: ${pkg.filePath}`);
                }
                logger.info(`   Reason: ${pkg.reason}`);
                logger.info('');
            });
            
            logger.info('=== END REPORT ===');
            
            // Show output panel
            vscode.commands.executeCommand('workbench.action.output.show');
        } else if (action === 'Copy Details') {
            // Copy detailed information to clipboard
            const reportText = [
                '=== DENIED PACKAGES REPORT ===',
                '',
                `Total denied packages: ${newDeniedPackages.length}`,
                '',
                ...newDeniedPackages.map((pkg, index) => [
                    `${index + 1}. ${pkg.name}${pkg.version ? '@' + pkg.version : ''}`,
                    `   Ecosystem: ${pkg.ecosystem}`,
                    pkg.filePath ? `   Location: ${pkg.filePath}` : null,
                    `   Reason: ${pkg.reason}`,
                    ''
                ].filter(Boolean).join('\n'))
            ].join('\n');
            
            await vscode.env.clipboard.writeText(reportText);
            vscode.window.showInformationMessage('Denied packages report copied to clipboard');
        }

        // Also show notification via NotificationManager
        this.notifications.showWarning(
            `${alert.title}: ${newDeniedPackages.length} package(s) detected`
        );
    }

    /**
     * Reset notification tracking (for testing)
     */
    resetNotifications(): void {
        this.notifiedPackages.clear();
        logger.info('Heartbeat notification tracking reset');
    }

    /**
     * Check if service is running
     */
    isActive(): boolean {
        return this.isRunning;
    }
}
