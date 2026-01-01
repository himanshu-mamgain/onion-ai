import { OnionConfig, SecurityResult } from '../config';

export class Privacy {
    constructor(private config: OnionConfig['piiProtection']) { }

    anonymize(input: string): SecurityResult {
        if (!this.config.enabled) return { safe: true, threats: [], riskScore: 0 };

        let sanitizedValue = input;
        const threats: string[] = [];

        // Regex patterns for PII
        // Note: Global flags used for replacer. For .test() checks, it's safer to just run replace and check modification or match.
        const patterns: Record<string, RegExp> = {
            email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
            phone: /\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
            creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
            ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
            ip: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g
        };

        const maskMap: Record<string, string> = {
            email: '[EMAIL_REDACTED]',
            phone: '[PHONE_REDACTED]',
            creditCard: '[CARD_REDACTED]',
            ssn: '[SSN_REDACTED]',
            ip: '[IP_REDACTED]'
        };

        if (this.config.maskEmail) {
            if (sanitizedValue.match(patterns.email)) {
                sanitizedValue = sanitizedValue.replace(patterns.email, maskMap.email);
                threats.push("PII Detected: Email Address");
            }
        }

        if (this.config.maskPhone) {
            if (sanitizedValue.match(patterns.phone)) {
                sanitizedValue = sanitizedValue.replace(patterns.phone, maskMap.phone);
                threats.push("PII Detected: Phone Number");
            }
        }

        if (this.config.maskCreditCard) {
            if (sanitizedValue.match(patterns.creditCard)) {
                sanitizedValue = sanitizedValue.replace(patterns.creditCard, maskMap.creditCard);
                threats.push("PII Detected: Credit Card Number");
            }
        }

        if (this.config.maskSSN) {
            if (sanitizedValue.match(patterns.ssn)) {
                sanitizedValue = sanitizedValue.replace(patterns.ssn, maskMap.ssn);
                threats.push("PII Detected: SSN");
            }
        }

        if (this.config.maskIP) {
            if (sanitizedValue.match(patterns.ip)) {
                sanitizedValue = sanitizedValue.replace(patterns.ip, maskMap.ip);
                threats.push("PII Detected: IP Address");
            }
        }

        // Custom Validators (Phase 1.1)
        if (this.config.custom && this.config.custom.length > 0) {
            for (const validator of this.config.custom) {
                // Regex Pattern Strategy
                if (validator.pattern) {
                    if (sanitizedValue.match(validator.pattern)) {
                        const replacement = validator.replaceWith || `[${validator.name.toUpperCase()}_REDACTED]`;
                        sanitizedValue = sanitizedValue.replace(validator.pattern, replacement);
                        threats.push(`PII Detected: Custom (${validator.name})`);
                    }
                }
                // Function Validator Strategy (Simple Check)
                else if (validator.validator) {
                    // Logic for validator function is harder for replacement unless it returns indices.
                    // For now, we assume it just FLAGS it, unless we scan word by word?
                    // Let's keep it simple: if it returns true, we flag it. Modification is hard without location.
                    if (validator.validator(input)) {
                        threats.push(`PII Detected: Custom (${validator.name}) - Detected by Validator`);
                    }
                }
            }
        }

        return {
            safe: threats.length === 0, // It is technically "safe" now that it is redacted, but we flag the threat presence
            threats,
            sanitizedValue,
            riskScore: threats.length > 0 ? 0.6 : 0
        };
    }
}
