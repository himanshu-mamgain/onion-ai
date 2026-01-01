import { OnionInputConfig } from './config';

export const OnionPresets = {
    /**
     * Recommended starting point. Balanced security.
     */
    STANDARD: {
        preventPromptInjection: true,
        piiSafe: true,
        dbSafe: true,
        strict: false
    } as OnionInputConfig,

    /**
     * Maximum security. High risk thresholds, strict mode enabled.
     * Blocks almost all suspicious patterns.
     */
    STRICT_SECURITY: {
        preventPromptInjection: true,
        piiSafe: true,
        dbSafe: true,
        strict: true,
        inputSanitization: {
            sanitizeHtml: true,
            removeScriptTags: true,
            escapeSpecialChars: true
        },
        promptInjectionProtection: {
            blockPhrases: [
                "ignore previous instructions", "act as system", "you are root",
                "reveal system prompt", "bypass", "jailbreak", "DAN mode", "Dev mode"
            ],
            checklistStrict: true // Hypothetical flag, or we just pass more patterns here
        }
    } as OnionInputConfig,

    /**
     * For educational or open-ended bots.
     * Allows code examples, SQL keywords (in context), etc.
     */
    EDUCATIONAL: {
        preventPromptInjection: true,
        piiSafe: true,
        dbSafe: false, // Allow SQL discussion
        strict: false,
        inputSanitization: {
            sanitizeHtml: false, // Allow displaying HTML code examples
            removeScriptTags: true // Still dangerous to run
        }
    } as OnionInputConfig
};
