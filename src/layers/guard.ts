import { OnionConfig, SecurityResult } from '../config';

export class Guard {
    constructor(private config: OnionConfig['promptInjectionProtection']) { }

    check(input: string): SecurityResult {
        const threats: string[] = [];
        let riskScore = 0.0;
        const lowerInput = input.toLowerCase();
        const normalizedInput = this.normalize(input);

        // Positive Risk Factors (Raise Risk)
        // 1. Blocked Phrases (Highest weighting)
        for (const phrase of this.config.blockPhrases) {
            if (lowerInput.includes(phrase.toLowerCase())) {
                threats.push(`Blocked phrase detected: "${phrase}"`);
                riskScore += 1.0;
            }
            const normalizedPhrase = this.normalize(phrase);
            if (normalizedInput.includes(normalizedPhrase) && !lowerInput.includes(phrase.toLowerCase())) {
                threats.push(`Obfuscated blocked phrase detected: "${phrase}"`);
                riskScore += 0.9;
            }
        }

        // 2. Heuristics (Medium weighting 0.4 - 0.7)
        const injectionPatterns = [
            { pattern: /translate\s+the\s+above/i, weight: 0.4 },
            { pattern: /ignore\s+(all\s+|those\s+)?(previous\s+|safety\s+)?(instructions|restrictions|rules)/i, weight: 0.9 }, // PI-001, PI-008
            { pattern: /judge\s+by\s+your\s+rules/i, weight: 0.5 },
            { pattern: /instead\s+of/i, weight: 0.3 },
            { pattern: /system\s+prompt/i, weight: 0.6 },
            { pattern: /you\s+are\s+(now\s+)?(a\s+)?(system|admin|root|developer)/i, weight: 0.8 }, // PI-003
            { pattern: /this\s+is\s+the\s+(developer|admin|system)/i, weight: 0.8 }, // PI-004
            { pattern: /break\s+(previous\s+)?(rules|instructions)/i, weight: 0.8 }, // PI-004 support
            { pattern: /disregard\s+(all\s+)?(safety\s+)?(instructions|rules|protocols)/i, weight: 0.9 },
            { pattern: /bypass\s+(restrictions|rules|controls)/i, weight: 0.9 },
            { pattern: /not\s+bound\s+by/i, weight: 0.8 }, // PI-006
            { pattern: /DAN\s+Mode/i, weight: 0.9 },
            { pattern: /do\s+anything\s+now/i, weight: 0.9 },
            { pattern: /reveal\s+(hidden\s+)?(instructions|rules|system)/i, weight: 0.9 }, // PI-007
            { pattern: /disable\s+(all\s+)?(safety\s+)?rules/i, weight: 0.9 } // PI-003
        ];

        for (const item of injectionPatterns) {
            if (item.pattern.test(input)) {
                threats.push(`Potential prompt injection pattern detected: ${item.pattern}`);
                riskScore += item.weight;
            }
        }

        // 3. Semantic Analysis (Context Awareness)
        // Reduce risk if user seems to be asking for educational content.
        // E.g. "How do I prevent 'ignore previous instructions'?"
        const educationalContexts = [
            "how to prevent",
            "how do i prevent",
            "example of",
            "what is a",
            "explain the attack",
            "security research"
        ];

        let safeContextFound = false;
        for (const context of educationalContexts) {
            if (lowerInput.includes(context)) {
                safeContextFound = true;
                break;
            }
        }

        if (safeContextFound) {
            // Apply semantic reduction. 
            // If the risk score was raised purely by words like "ignore previous", we assume it's a false positive.
            if (riskScore > 0 && riskScore < 1.5) { // If slightly suspicious but education context found
                threats.push("Semantic Context: Detected educational/prevention context. Reducing risk.");
                riskScore = Math.max(0, riskScore - 0.5); // Reduce risk significantly
            }
        }

        // Cap Risk Score
        riskScore = Math.min(1.0, riskScore);

        return {
            safe: threats.length === 0 || (safeContextFound && riskScore < 0.5),
            threats,
            riskScore
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
