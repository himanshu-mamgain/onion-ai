import { OnionConfig, SecurityResult } from '../config';

export class Guard {
    constructor(private config: OnionConfig['promptInjectionProtection']) { }

    check(input: string): SecurityResult {
        const threats: string[] = [];
        const lowerInput = input.toLowerCase();

        // Check for blocked phrases
        for (const phrase of this.config.blockPhrases) {
            if (lowerInput.includes(phrase.toLowerCase())) {
                threats.push(`Blocked phrase detected: "${phrase}"`);
            }
        }

        // Heuristics for prompt injection
        const injectionPatterns = [
            /translate the above/i,
            /ignore all previous/i,
            /instead of/i,
            /system prompt/i,
            /you are now/i,
            /disregard/i,
            /bypass/i
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
}
