import { OnionConfig, SecurityResult } from '../config';

export class Validator {
    constructor(private config: OnionConfig['outputValidation']) { }

    validateOutput(output: string): SecurityResult {
        const threats: string[] = [];
        let riskScore = 0.0;
        let validatedOutput = output;

        // Helper to check and potentially repair
        const matchAndHandle = (pattern: RegExp, name: string, score: number, replacement: string) => {
            // Use a clone to test or just match?
            // If global regex, matchAll. If not, test.
            // The patterns defined below are mostly regex literals without 'g'.
            // To replace all invoke 'g'.
            const globalPattern = new RegExp(pattern, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');

            if (globalPattern.test(validatedOutput)) {
                threats.push(`${name} detected in output`);
                riskScore = Math.max(riskScore, score);

                if (this.config.repair) {
                    validatedOutput = validatedOutput.replace(globalPattern, replacement);
                }
            }
        };

        if (this.config.checkPII) {
            const piiPatterns = [
                { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, name: "PII (SSN)", score: 0.9 },
                { pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, name: "PII (Email)", score: 0.7 },
                { pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, name: "PII (Credit Card)", score: 0.9 },
                { pattern: /\b1\d{2}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, name: "Potential Internal IP", score: 0.6 }
            ];

            for (const item of piiPatterns) {
                matchAndHandle(item.pattern, item.name, item.score, "[PII_REDACTED]");
            }
        }

        if (this.config.preventDataLeak) {
            const apiKeyPatterns = [
                { pattern: /sk-[a-zA-Z0-9]{32,}/g, name: "OpenAI API Key" },
                { pattern: /AIza[a-zA-Z0-9_-]{35}/g, name: "Google API Key" },
                { pattern: /AKIA[0-9A-Z]{16}/g, name: "AWS Access Key" },
                { pattern: /ghp_[a-zA-Z0-9]{36}/g, name: "GitHub Token" },
                { pattern: /xox[baprs]-[a-zA-Z0-9]{10,48}/g, name: "Slack Token" }
            ];

            for (const item of apiKeyPatterns) {
                matchAndHandle(item.pattern, `Data Leak (${item.name})`, 1.0, "[SECRET_REDACTED]");
            }
        }

        if (this.config.blockMaliciousCommands) {
            const maliciousCommands = [
                /rm -rf /gi,
                /format c:/gi,
                /:(){:|:&};:/g, // Fork bomb
                /chmod 777 /gi,
                /wget http/gi,
                /curl http/gi
            ];

            for (const pattern of maliciousCommands) {
                // Malicious commands cannot simply be 'redacted' to make the output safe in a functional sense, 
                // but we can neutralize them.
                matchAndHandle(pattern, "Malicious command", 1.0, "[BLOCKED_COMMAND]");
            }
        }

        // Logic for return:
        // If repair is ON, and we substituted everything, is it safe?
        // If riskScore > 0, we found threats.
        // If repair is TRUE, we consider the output 'sanitized' and thus safe to consume (technically),
        // but we still return threats so the calling app knows.
        // However, standard protocol: safe=true means "Go ahead".
        const safe = this.config.repair ? true : threats.length === 0;

        return {
            safe,
            threats,
            riskScore: this.config.repair ? 0 : riskScore, // If repaired, risk is mitigated? Or keep score? Keep score for auditing.
            sanitizedValue: validatedOutput
        };
    }
}
