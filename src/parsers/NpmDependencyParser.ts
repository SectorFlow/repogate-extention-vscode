import { BaseDependencyParser } from './DependencyParser';
import { DependencyInfo } from '../models/DependencyInfo';

export class NpmDependencyParser extends BaseDependencyParser {
    supports(fileName: string): boolean {
        return fileName === 'package.json';
    }

    parseNewDependencies(content: string, previousContent: string): DependencyInfo[] {
        const newDeps: DependencyInfo[] = [];

        try {
            const previousDeps = this.extractDependenciesWithVersions(previousContent);
            const currentDeps = this.extractDependenciesWithVersions(content);

            // Check for new packages and version changes
            for (const [packageName, version] of currentDeps.entries()) {
                const previousVersion = previousDeps.get(packageName);
                
                if (!previousVersion) {
                    // New package added
                    newDeps.push(this.createDependencyInfo(packageName, version));
                } else if (previousVersion !== version) {
                    // Version changed (upgrade or downgrade)
                    newDeps.push(this.createDependencyInfo(packageName, version));
                }
            }
        } catch (error) {
            console.error('Error parsing npm dependencies:', error);
        }

        return newDeps;
    }

    /**
     * Extract dependencies with their versions
     */
    private extractDependenciesWithVersions(content: string): Map<string, string> {
        const deps = new Map<string, string>();

        if (!content || content.trim() === '') {
            return deps;
        }

        try {
            const json = JSON.parse(content);

            if (json.dependencies) {
                Object.entries(json.dependencies).forEach(([name, version]) => {
                    deps.set(name, version as string);
                });
            }

            if (json.devDependencies) {
                Object.entries(json.devDependencies).forEach(([name, version]) => {
                    deps.set(name, version as string);
                });
            }
        } catch (error) {
            // Ignore parsing errors
        }

        return deps;
    }

    /**
     * Legacy method for backward compatibility
     */
    private extractDependencies(content: string): Set<string> {
        const deps = new Set<string>();

        if (!content || content.trim() === '') {
            return deps;
        }

        try {
            const json = JSON.parse(content);

            if (json.dependencies) {
                Object.keys(json.dependencies).forEach(dep => deps.add(dep));
            }

            if (json.devDependencies) {
                Object.keys(json.devDependencies).forEach(dep => deps.add(dep));
            }
        } catch (error) {
            // Ignore parsing errors
        }

        return deps;
    }

    parseAllDependencies(content: string): DependencyInfo[] {
        const allDeps: DependencyInfo[] = [];

        try {
            const json = JSON.parse(content);
            const dependencies = {
                ...json.dependencies,
                ...json.devDependencies
            };

            for (const [packageName, version] of Object.entries(dependencies)) {
                allDeps.push(this.createDependencyInfo(packageName, version as string));
            }
        } catch (error) {
            console.error('Error parsing all npm dependencies:', error);
        }

        return allDeps;
    }

    getPackageManager(): string {
        return 'npm';
    }
}
