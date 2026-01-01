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

        // If read-only mode, we need to be careful not to flag natural language.
        // We only enforce "Must be SELECT" if the input actually looks like a SQL command.
        if (this.config.mode === 'read-only') {
            const firstWord = upperQuery.split(/\s+/)[0];
            const sqlCommands = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "GRANT", "REVOKE", "TRUNCATE", "MERGE", "REPLACE", "Upsert"];

            // If it starts with a known SQL command that ISN'T Select, flag it.
            // If it starts with "Hello", we ignore it (unless it hits a forbidden marker later).
            if (sqlCommands.includes(firstWord)) {
                threats.push(`Non-SELECT query detected in read-only mode (starts with ${firstWord})`);
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
