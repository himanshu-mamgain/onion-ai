import { OnionConfig, SecurityResult } from '../config';

export interface PIImap {
    [token: string]: string;
}

const REGEX_REGISTRY: Record<string, Record<string, RegExp>> = {
    'US': {
        email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
        phone: /\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
        creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
        ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
        ip: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g
    },
    'IN': {
        // Indian Formats
        phone: /\b(\+91[\-\s]?)?[6789]\d{9}\b/g,
        pan: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g,
        aadhaar: /\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b/g,
        ifsc: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g
    },
    'EU': {
        // Generic Euro/GDPR helpers (IBAN is variable length, simple check here)
        iban: /\b[A-Z]{2}[0-9]{2}[a-zA-Z0-9]{4}[0-9]{7}([a-zA-Z0-9]?){0,16}\b/g
    }
};

export class Privacy {
    constructor(private config: OnionConfig['piiProtection']) { }

    anonymize(input: string): SecurityResult {
        if (!this.config.enabled) return { safe: true, threats: [], riskScore: 0 };

        let sanitizedValue = input;
        const threats: string[] = [];
        const piiMap: PIImap = {};

        // Helper to replace and store if reversible
        const replace = (pattern: RegExp, type: string, mask: string) => {
            if (!sanitizedValue.match(pattern)) return;

            sanitizedValue = sanitizedValue.replace(pattern, (match) => {
                threats.push(`PII Detected: ${type.toUpperCase()}`);

                if (this.config.reversible) {
                    // Create a deterministic-ish token for this request? 
                    // Or simple counter. Simple counter per request.
                    const token = `{{${type.toUpperCase()}_${Object.keys(piiMap).length + 1}}}`;
                    piiMap[token] = match;
                    return token;
                } else {
                    return mask;
                }
            });
        };

        const activeLocales = this.config.locale || ['US'];

        // 1. Standard Fields (based on locale)
        activeLocales.forEach(loc => {
            const registry = REGEX_REGISTRY[loc] || REGEX_REGISTRY['US'];

            if (this.config.maskEmail && registry.email) replace(registry.email, 'EMAIL', '[EMAIL_REDACTED]');
            // Email is universal, but sometimes stored in US. Fallback to US if not in locale.
            if (this.config.maskEmail && !registry.email) replace(REGEX_REGISTRY['US'].email, 'EMAIL', '[EMAIL_REDACTED]');

            if (this.config.maskPhone) {
                replace(registry.phone || REGEX_REGISTRY['US'].phone, 'PHONE', '[PHONE_REDACTED]');
            }

            if (this.config.maskSSN) {
                // Determine pattern based on locale key
                let pattern = registry.ssn;
                let name = 'SSN';
                if (loc === 'IN') { pattern = registry.aadhaar; name = 'AADHAAR'; }
                if (pattern) replace(pattern, name, `[${name}_REDACTED]`);
            }

            if (loc === 'IN') {
                if (registry.pan) replace(registry.pan, 'PAN', '[PAN_REDACTED]');
                if (registry.ifsc) replace(registry.ifsc, 'IFSC', '[IFSC_REDACTED]');
            }
            if (loc === 'EU') {
                if (registry.iban) replace(registry.iban, 'IBAN', '[IBAN_REDACTED]');
            }
        });

        // 2. Global Fields (CC, IP, Secrets) - usually standard regex
        // Resetting to US for standard if not active? Actually CC and IP are fairly universal standard
        if (this.config.maskCreditCard) replace(REGEX_REGISTRY['US'].creditCard, 'CREDIT_CARD', '[CARD_REDACTED]');
        if (this.config.maskIP) replace(REGEX_REGISTRY['US'].ip, 'IP', '[IP_REDACTED]');

        // 3. Secrets (Critical - always redact, never reversible?) 
        // Logic: Secrets should never go to LLM. But if reversible is ON, maybe we want to put them back? 
        // No, typically you don't want to round-trip secrets through an LLM flow even as tokens if you can avoid it, 
        // but for "reversible" uniformity, we might allow it. 
        // Let's keep secrets IRREVERSIBLE for safety unless explicitly asked? 
        // For now, let's treat them as standard PII.
        if (this.config.detectSecrets) {
            const secretPatterns: Record<string, RegExp> = {
                openai: /sk-[a-zA-Z0-9]{20,}/g,
                github: /gh[pousr]_[a-zA-Z0-9]{36,}/g,
                aws: /\bAKIA[0-9A-Z]{16}\b/g,
                privateKey: /-----BEGIN [A-Z ]+ PRIVATE KEY-----/g
            };
            for (const [key, pattern] of Object.entries(secretPatterns)) {
                // Secrets are high risk, we force redaction usually. 
                // We will NOT put them in the map for safety.
                if (sanitizedValue.match(pattern)) {
                    sanitizedValue = sanitizedValue.replace(pattern, `[SECRET_${key.toUpperCase()}_REDACTED]`);
                    threats.push(`CRITICAL: ${key.toUpperCase()} API Key/Secret Detected`);
                }
            }
        }

        // 4. Custom Validators
        if (this.config.custom) {
            this.config.custom.forEach(validator => {
                if (validator.pattern) {
                    replace(validator.pattern, validator.name, validator.replaceWith || `[${validator.name.toUpperCase()}_REDACTED]`);
                }
            });
        }

        let riskScore = (threats.length > 0) ? 0.6 : 0;
        // Check for critical secrets
        if (threats.some(t => t.includes('CRITICAL'))) riskScore = 1.0;

        return {
            safe: threats.length === 0, // safe=false if PII found, even if redacted/tokenized
            threats,
            sanitizedValue,
            riskScore,
            metadata: {
                piiMap: this.config.reversible ? piiMap : undefined
            }
        };
    }
}
