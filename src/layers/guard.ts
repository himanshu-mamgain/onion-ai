import { OnionConfig, SecurityResult } from '../config';

export class Guard {
    constructor(private config: OnionConfig['promptInjectionProtection']) { }

    check(input: string): SecurityResult {
        const threats: string[] = [];
        const lowerInput = input.toLowerCase();
        const normalizedInput = this.normalize(input);

        // Check for blocked phrases (Standard)
        for (const phrase of this.config.blockPhrases) {
            if (lowerInput.includes(phrase.toLowerCase())) {
                threats.push(`Blocked phrase detected: "${phrase}"`);
            }
            // Check for obfuscated blocked phrases
            const normalizedPhrase = this.normalize(phrase);
            if (normalizedInput.includes(normalizedPhrase) && !lowerInput.includes(phrase.toLowerCase())) {
                threats.push(`Obfuscated blocked phrase detected: "${phrase}" (hidden as "${this.findHiddenMatch(input, phrase)}")`);
            }
        }

        // Heuristics for prompt injection
        const injectionPatterns = [
            /translate\s+the\s+above/i,
            /ignore\s+all\s+previous/i,
            /instead\s+of/i,
            /system\s+prompt/i,
            /you\s+are\s+now/i,
            /disregard\s+instructions/i,
            /bypass\s+restrictions/i,
            /DAN\s+Mode/i,
            /do\s+anything\s+now/i
        ];

        for (const pattern of injectionPatterns) {
            if (pattern.test(input)) {
                threats.push(`Potential prompt injection pattern detected: ${pattern}`);
            }
        }

        return {
            safe: threats.length === 0,
            threats
        };
    }

    private normalize(input: string): string {
        // Remove all non-alphanumeric characters to catch spacing/masking
        return input.toLowerCase().replace(/[^a-z0-9]/g, '');
    }

    // Helper to find somewhat where the match occurred for reporting, although imprecise
    private findHiddenMatch(input: string, phrase: string): string {
        // This is just a placeholder for better reporting, simple substring is hard due to spacing
        return "pattern match";
    }
}
