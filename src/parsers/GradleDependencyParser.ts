import { BaseDependencyParser } from './DependencyParser';
import { DependencyInfo } from '../models/DependencyInfo';

export class GradleDependencyParser extends BaseDependencyParser {
    private readonly DEPENDENCY_PATTERN = /(?:implementation|api|compile|testImplementation|runtimeOnly|compileOnly)\s*[\(\s]*['"]([^:'"]+):([^:'"]+)(?::([^'"]+))?['"]/gm;

    supports(fileName: string): boolean {
        return fileName === 'build.gradle' || fileName === 'build.gradle.kts';
    }

    parseNewDependencies(content: string, previousContent: string): DependencyInfo[] {
        const newDeps: DependencyInfo[] = [];

        try {
            const previousDeps = this.extractDependenciesWithVersions(previousContent);
            const currentDeps = this.extractDependenciesWithVersions(content);

            // Check for new packages and version changes
            for (const [fullName, version] of currentDeps.entries()) {
                const previousVersion = previousDeps.get(fullName);
                
                if (!previousVersion) {
                    // New package added
                    newDeps.push(this.createDependencyInfo(fullName, version));
                } else if (previousVersion !== version) {
                    // Version changed (upgrade or downgrade)
                    newDeps.push(this.createDependencyInfo(fullName, version));
                }
            }
        } catch (error) {
            console.error('Error parsing Gradle dependencies:', error);
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
            const matches = content.matchAll(this.DEPENDENCY_PATTERN);
            for (const match of matches) {
                const groupId = match[1].trim();
                const artifactId = match[2].trim();
                const version = match[3] ? match[3].trim() : '';
                const fullName = `${groupId}:${artifactId}`;
                deps.set(fullName, version);
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
            const matches = content.matchAll(this.DEPENDENCY_PATTERN);
            for (const match of matches) {
                const groupId = match[1].trim();
                const artifactId = match[2].trim();
                deps.add(`${groupId}:${artifactId}`);
            }
        } catch (error) {
            // Ignore parsing errors
        }

        return deps;
    }

    parseAllDependencies(content: string): DependencyInfo[] {
        const allDeps: DependencyInfo[] = [];

        try {
            const matches = content.matchAll(this.DEPENDENCY_PATTERN);
            for (const match of matches) {
                const groupId = match[1].trim();
                const artifactId = match[2].trim();
                const version = match[3] ? match[3].trim() : '';
                const fullName = `${groupId}:${artifactId}`;
                allDeps.push(this.createDependencyInfo(fullName, version));
            }
        } catch (error) {
            console.error('Error parsing all Gradle dependencies:', error);
        }

        return allDeps;
    }

    getPackageManager(): string {
        return 'gradle';
    }
}
