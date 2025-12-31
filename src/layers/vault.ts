import { OnionConfig, SecurityResult } from '../config';

export class Vault {
    constructor(private config: OnionConfig['dbProtection']) { }

    checkSQL(query: string): SecurityResult {
        if (!this.config.enabled) return { safe: true, threats: [] };

        const threats: string[] = [];
        const upperQuery = query.toUpperCase();

        // Check for forbidden statements
        for (const statement of this.config.forbiddenStatements) {
            if (upperQuery.includes(statement.toUpperCase())) {
                threats.push(`Forbidden SQL statement detected: ${statement}`);
            }
        }

        // If read-only mode, only SELECT is usually allowed
        if (this.config.mode === 'read-only') {
            const isSelect = upperQuery.trim().startsWith('SELECT');
            if (!isSelect && query.trim().length > 0) {
                threats.push("Non-SELECT query detected in read-only mode");
            }
        }

        // Check for common SQL injection markers
        const sqlInjectionMarkers = [
            /--/,
            /\/\*/,
            /;\s*DROP/i,
            /UNION\s+SELECT/i,
            /'\s*OR\s*'\d+'\s*=\s*'\d+/i
        ];

        for (const marker of sqlInjectionMarkers) {
            if (marker.test(query)) {
                threats.push(`Potential SQL injection marker detected: ${marker}`);
            }
        }

        return {
            safe: threats.length === 0,
            threats
        };
    }
}
