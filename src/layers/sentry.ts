import { OnionConfig, SecurityResult } from '../config';

export class Sentry {
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
