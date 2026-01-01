import { OnionConfig, SecurityResult } from '../config';

export class Vault {
    constructor(private config: OnionConfig['dbProtection']) { }

    checkSQL(query: string): SecurityResult {
        if (!this.config.enabled) return { safe: true, threats: [], riskScore: 0 };

        const threats: string[] = [];
        let riskScore = 0.0;
        const upperQuery = query.toUpperCase();

        // 1. Forbidden Keywords (Critical)
        for (const statement of this.config.forbiddenStatements) {
            const regex = new RegExp(`\\b${statement}\\b`, 'i');
            if (regex.test(query)) {
                threats.push(`Forbidden SQL statement detected: ${statement}`);
                riskScore += 1.0;
            }
        }

        // 2. Read-Only Enforcement (Moderate)
        if (this.config.mode === 'read-only') {
            const firstWord = upperQuery.split(/\s+/)[0];
            const sqlCommands = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "GRANT", "REVOKE", "TRUNCATE", "MERGE", "REPLACE", "UPSERT"];

            if (sqlCommands.includes(firstWord)) {
                threats.push(`Non-SELECT query detected in read-only mode (starts with ${firstWord})`);
                riskScore += 0.8;
            }
        }

        // 3. Injection Markers (High)
        const sqlInjectionMarkers = [
            { pattern: /--/, weight: 0.6 },
            { pattern: /\/\*/, weight: 0.6 },
            { pattern: /;\s*DROP/i, weight: 1.0 },
            { pattern: /UNION\s+SELECT/i, weight: 1.0 },
            { pattern: /'\s*OR\s*'\d+'\s*=\s*'\d+/i, weight: 1.0 },
            { pattern: /'\s*=\s*'/i, weight: 0.8 }
        ];

        for (const item of sqlInjectionMarkers) {
            if (item.pattern.test(query)) {
                threats.push(`Potential SQL injection marker detected: ${item.pattern}`);
                riskScore += item.weight;
            }
        }

        riskScore = Math.min(1.0, riskScore);

        return {
            safe: threats.length === 0,
            threats,
            riskScore
        };
    }
}
