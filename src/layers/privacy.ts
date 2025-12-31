import { OnionConfig, SecurityResult } from '../config';

export class Privacy {
    constructor(private config: OnionConfig['piiProtection']) { }

    anonymize(input: string): SecurityResult {
        if (!this.config.enabled) return { safe: true, threats: [] };

        let sanitizedValue = input;
        const threats: string[] = [];

        // Regex patterns for PII
        const patterns: Record<string, RegExp> = {
            email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            phone: /\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
            creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
            ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
            ip: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g // Simple IPv4
        };

        const maskMap: Record<string, string> = {
            email: '[EMAIL_REDACTED]',
            phone: '[PHONE_REDACTED]',
            creditCard: '[CARD_REDACTED]',
            ssn: '[SSN_REDACTED]',
            ip: '[IP_REDACTED]'
        };

        if (this.config.maskEmail) {
            if (patterns.email.test(sanitizedValue)) {
                sanitizedValue = sanitizedValue.replace(patterns.email, maskMap.email);
                threats.push("PII Detected: Email Address");
            }
        }

        if (this.config.maskPhone) {
            if (patterns.phone.test(sanitizedValue)) {
                sanitizedValue = sanitizedValue.replace(patterns.phone, maskMap.phone);
                threats.push("PII Detected: Phone Number");
            }
        }

        if (this.config.maskCreditCard) {
            if (patterns.creditCard.test(sanitizedValue)) {
                sanitizedValue = sanitizedValue.replace(patterns.creditCard, maskMap.creditCard);
                threats.push("PII Detected: Credit Card Number");
            }
        }

        if (this.config.maskSSN) {
            if (patterns.ssn.test(sanitizedValue)) {
                sanitizedValue = sanitizedValue.replace(patterns.ssn, maskMap.ssn);
                threats.push("PII Detected: SSN");
            }
        }

        if (this.config.maskIP) {
            if (patterns.ip.test(sanitizedValue)) {
                sanitizedValue = sanitizedValue.replace(patterns.ip, maskMap.ip);
                threats.push("PII Detected: IP Address");
            }
        }

        return {
            safe: threats.length === 0, // It is technically "safe" now that it is redacted, but we flag the threat presence
            threats,
            sanitizedValue
        };
    }
}
