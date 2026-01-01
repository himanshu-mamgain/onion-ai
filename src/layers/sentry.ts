import { OnionConfig, SecurityResult } from '../config';

export class Sentry {
    private sessionHistory: Map<string, { hash: string, timestamp: number }[]> = new Map();

    checkSessionHistory(sessionId: string, prompt: string): { riskIncrease: number; warnings: string[] } {
        const now = Date.now();
        const hash = this.simpleHash(prompt);
        let history = this.sessionHistory.get(sessionId) || [];

        // 1. Cleanup old history (last 5 minutes window)
        history = history.filter(h => now - h.timestamp < 300000);

        // 2. Check Frequency
        const recentRequests = history.length;
        let riskIncrease = 0.0;
        const warnings: string[] = [];

        if (recentRequests > 10) {
            riskIncrease += 0.2;
            warnings.push("High frequency of requests in session");
        }
        if (recentRequests > 20) {
            riskIncrease += 1.0; // Auto block
            warnings.push("Session flood detected (Possible DoS/Brute Force)");
        }

        // 3. Check Repetition (Brute Force Jailbreaking often involves repeating similar prompts)
        const repetitionCount = history.filter(h => h.hash === hash).length;
        if (repetitionCount > 2) {
            riskIncrease += 0.3;
            warnings.push("Repetitive prompt detected (Possible Brute Force)");
        }

        history.push({ hash, timestamp: now });
        this.sessionHistory.set(sessionId, history);

        return { riskIncrease, warnings };
    }

    private simpleHash(str: string): string {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return hash.toString(16);
    }
    private requestHistory: { timestamp: number }[] = [];

    constructor(private config: OnionConfig['rateLimitingAndResourceControl']) { }

    checkRateLimit(): SecurityResult {
        const now = Date.now();
        const oneMinuteAgo = now - 60000;

        // Cleanup old history
        this.requestHistory = this.requestHistory.filter(r => r.timestamp > oneMinuteAgo);

        if (this.requestHistory.length >= this.config.maxRequestsPerMinute) {
            return {
                safe: false,
                threats: ["Rate limit exceeded (Max requests per minute)"],
                riskScore: 1.0
            };
        }

        this.requestHistory.push({ timestamp: now });
        return { safe: true, threats: [], riskScore: 0 };
    }

    checkTokenCount(prompt: string): SecurityResult {
        const threats: string[] = [];
        // Simple estimation: 1 word ~ 1.3 tokens or just character count / 4
        const estimatedTokens = Math.ceil(prompt.length / 4);

        if (estimatedTokens > this.config.maxTokensPerPrompt) {
            threats.push(`Prompt exceeds max token limit (${estimatedTokens} > ${this.config.maxTokensPerPrompt})`);
        }

        return {
            safe: threats.length === 0,
            threats,
            metadata: { estimatedTokens },
            riskScore: threats.length > 0 ? 0.3 : 0
        };
    }
}
