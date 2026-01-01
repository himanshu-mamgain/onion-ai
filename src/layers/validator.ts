import { OnionConfig, SecurityResult } from '../config';

export class Validator {
    constructor(private config: OnionConfig['outputValidation']) { }

    validateOutput(output: string): SecurityResult {
        const threats: string[] = [];
        let riskScore = 0.0;

        if (this.config.checkPII) {
            const piiPatterns = [
                { pattern: /\b\d{3}-\d{2}-\d{4}\b/, name: "SSN", score: 0.9 },
                { pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i, name: "Email", score: 0.7 },
                { pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/, name: "Credit Card", score: 0.9 },
                { pattern: /\b1\d{2}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, name: "Internal IP Pattern", score: 0.6 } // Very rough check
            ];

            for (const item of piiPatterns) {
                if (item.pattern.test(output)) {
                    threats.push(`Potential PII (${item.name}) detected in output`);
                    riskScore = Math.max(riskScore, item.score);
                }
            }
        }

        if (this.config.preventDataLeak) {
            const apiKeyPatterns = [
                { pattern: /sk-[a-zA-Z0-9]{32,}/, name: "OpenAI API Key" },
                { pattern: /AIza[a-zA-Z0-9_-]{35}/, name: "Google API Key" },
                { pattern: /AKIA[0-9A-Z]{16}/, name: "AWS Access Key" },
                { pattern: /ghp_[a-zA-Z0-9]{36}/, name: "GitHub Token" },
                { pattern: /xox[baprs]-[a-zA-Z0-9]{10,48}/, name: "Slack Token" }
            ];

            for (const item of apiKeyPatterns) {
                if (item.pattern.test(output)) {
                    threats.push(`Potential Data Leak (${item.name}) detected in output`);
                    riskScore = 1.0; // Critical leak
                }
            }
        }

        if (this.config.blockMaliciousCommands) {
            const maliciousCommands = [
                /rm -rf /i,
                /format c:/i,
                /:(){:|:&};:/, // Fork bomb
                /chmod 777 /i,
                /wget http/i,
                /curl http/i
            ];

            for (const pattern of maliciousCommands) {
                if (pattern.test(output)) {
                    threats.push("Malicious command detected in output");
                    riskScore = 1.0;
                }
            }
        }

        // We do typically want Redaction in secureResponse too, but that's a larger change to use the Privacy layer here.
        // For now, validator is purely a "Check".

        return {
            safe: threats.length === 0,
            threats,
            riskScore
        };
    }
}
