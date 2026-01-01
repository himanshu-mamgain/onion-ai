import { OnionConfig, SecurityResult } from '../config';
import * as xss from 'xss';
import validator from 'validator';

export class Sanitizer {
    constructor(private config: OnionConfig['inputSanitization']) { }

    sanitize(input: string): string {
        let sanitized = input;

        if (this.config.removeZeroWidthChars) {
            sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF]/g, '');
        }

        if (this.config.removeScriptTags || this.config.sanitizeHtml) {
            sanitized = xss.filterXSS(sanitized, {
                whiteList: this.config.sanitizeHtml ? {} : undefined, // empty whitelist means remove all tags if sanitizeHtml is true
                stripIgnoreTag: true,
                stripIgnoreTagBody: ['script']
            });
        }

        if (this.config.escapeSpecialChars) {
            // Basic escaping, but be careful not to break markdown if normalizemadown is also true
            // Usually, validator.escape is a bit aggressive.
            // We'll use a more targeted escaping if it's for AI prompts.
        }

        if (this.config.normalizeMarkdown) {
            // Basic normalization: trim, multiple newlines to double newlines
            sanitized = sanitized.trim().replace(/\n{3,}/g, '\n\n');
        }

        return sanitized;
    }

    validate(input: string): SecurityResult {
        const sanitizedValue = this.sanitize(input);
        const threats: string[] = [];

        if (input !== sanitizedValue) {
            threats.push("Sanitization modified the input (potential malicious patterns removed)");
        }

        return {
            safe: true, // Sanitization makes it "safe" by modification
            threats,
            sanitizedValue,
            riskScore: threats.length > 0 ? 0.1 : 0
        };
    }
}
