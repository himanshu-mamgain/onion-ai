import { OnionConfig, SecurityResult } from '../config';

export class Validator {
    constructor(private config: OnionConfig['outputValidation']) { }

    validateOutput(output: string): SecurityResult {
        const threats: string[] = [];

        if (this.config.checkPII) {
            const piiPatterns = [
                /\b\d{3}-\d{2}-\d{4}\b/, // SSN
                /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i, // Email
                /\b(?:\d{4}-){3}\d{4}\b/, // Credit Card
            ];

            for (const pattern of piiPatterns) {
                if (pattern.test(output)) {
                    threats.push("Potential PII (Sensitive Data) detected in output");
                    break;
                }
            }
        }

        if (this.config.preventDataLeak) {
            const apiKeyPatterns = [
                /sk-[a-zA-Z0-9]{32,}/, // OpenAI
                /AIza[a-zA-Z0-9_-]{35}/, // Google
            ];

            for (const pattern of apiKeyPatterns) {
                if (pattern.test(output)) {
                    threats.push("Potential API Key leak detected in output");
                    break;
                }
            }
        }

        if (this.config.blockMaliciousCommands) {
            const maliciousCommands = [
                /rm -rf/i,
                /format c:/i,
                /:(){:|:&};:/, // Fork bomb
                /chmod 777/i
            ];

            for (const pattern of maliciousCommands) {
                if (pattern.test(output)) {
                    threats.push("Malicious command detected in output");
                    break;
                }
            }
        }

        return {
            safe: threats.length === 0,
            threats
        };
    }
}
