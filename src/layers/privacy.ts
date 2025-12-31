import { OnionConfig, SecurityResult } from '../config';

export class Privacy {
    private config: OnionConfig['piiProtection'];

    constructor(config: OnionConfig['piiProtection']) {
        this.config = config;
    }

    /**
     * Redacts PII from the input string based on configuration.
     * Returns the redacted string and a list of threats (what was redacted).
     */
    anonymize(input: string): SecurityResult {
        if (!this.config.enabled) {
            return { safe: true, threats: [], sanitizedValue: input };
        }

        let redacted = input;
        const threats: string[] = [];

        // 1. Email Redaction
        if (this.config.maskEmail) {
            const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
            if (emailRegex.test(redacted)) {
                redacted = redacted.replace(emailRegex, '[EMAIL_REDACTED]');
                threats.push("PII Detected: Email address(es) redacted.");
            }
        }

        // 2. Phone Redaction
        // Matches forms like: 123-456-7890, (123) 456-7890, 123 456 7890, +1 123 456 7890
        if (this.config.maskPhone) {
            const phoneRegex = /\b(?:\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g;
            if (phoneRegex.test(redacted)) {
                redacted = redacted.replace(phoneRegex, '[PHONE_REDACTED]');
                threats.push("PII Detected: Phone number(s) redacted.");
            }
        }

        // 3. Credit Card
        // Matches 13-19 digits, possibly with dashes or spaces
        // We use a slightly stricter look to avoid redacting generic long numbers unless they look like CC groups
        if (this.config.maskCreditCard) {
            const ccRegex = /\b(?:\d{4}[ -]?){3}\d{4}\b/g;
            if (ccRegex.test(redacted)) {
                redacted = redacted.replace(ccRegex, '[CREDIT_CARD_REDACTED]');
                threats.push("PII Detected: Credit Card number(s) redacted.");
            }
        }

        // 4. SSN (Social Security Number - US)
        if (this.config.maskSSN) {
            const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
            if (ssnRegex.test(redacted)) {
                redacted = redacted.replace(ssnRegex, '[SSN_REDACTED]');
                threats.push("PII Detected: SSN(s) redacted.");
            }
        }

        // 5. IP Address (IPv4)
        if (this.config.maskIP) {
            const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
            if (ipRegex.test(redacted)) {
                redacted = redacted.replace(ipRegex, '[IP_REDACTED]');
                threats.push("PII Detected: IP Address(es) redacted.");
            }
        }

        return {
            safe: threats.length === 0, // Safe only if no PII found? Or safe because we redacted it?
            // Usually, "safe" means "ready to proceed". Since we redacted it, it IS safe to proceed. 
            // BUT, if the user wanted to know about threats, we return false to trigger warnings.
            // Let's stick to: if we modified it due to a threat, safe = false (so alerts can fire), but sanitizedValue is usable.
            threats,
            sanitizedValue: redacted
        };
    }
}
