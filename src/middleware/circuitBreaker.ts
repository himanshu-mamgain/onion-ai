import { LRUCache } from 'lru-cache';

export interface BudgetConfig {
    maxTokens: number;
    maxCost?: number; // Optional dollar limit (e.g. 0.02)
    windowMs?: number; // Default 60000 (1 min)
    costPer1kTokens?: number; // Default 0.002
}

export class BudgetExceededError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'BudgetExceededError';
    }
}

interface UserUsage {
    tokens: number;
    cost: number;
    lastReset: number;
}

export class CircuitBreaker {
    private cache: LRUCache<string, UserUsage>;
    private config: BudgetConfig;
    private windowMs: number;
    private costPer1kTokens: number;

    constructor(config: BudgetConfig) {
        this.config = config;
        this.windowMs = config.windowMs || 60000;
        this.costPer1kTokens = config.costPer1kTokens || 0.002;

        // LRU Cache for user tracking
        this.cache = new LRUCache<string, UserUsage>({
            max: 1000, // Track up to 1000 users active
            ttl: this.windowMs, // Expire after window
            ttlAutopurge: true
        });
    }

    checkLimit(userId: string, estimatedTokens: number): void {
        let usage = this.cache.get(userId);
        const now = Date.now();

        // Initialize if new or expired (though ttl handles expiry, we might need a reset logic if lru-cache keeps entry but we want rigorous window)
        // With ttlAutopurge in lru-cache v7+, getting an expired item returns undefined.
        if (!usage) {
            usage = { tokens: 0, cost: 0, lastReset: now };
        }

        // Sliding window notion: If we strictly want "in a 60-second window", LRU TTL is approximation because it resets on 'set' if updateAgeOnGet/default behavior varies. 
        // We'll stick to a simple bucket reset: if (now - lastReset > window) reset.
        if (now - usage.lastReset > this.windowMs) {
            usage = { tokens: 0, cost: 0, lastReset: now };
        }

        const estimatedCost = (estimatedTokens / 1000) * this.costPer1kTokens;

        // Check projected usage
        if (usage.tokens + estimatedTokens > this.config.maxTokens) {
            throw new BudgetExceededError(`Token budget exceeded for user ${userId}. Limit: ${this.config.maxTokens}, Current: ${usage.tokens}, Attempted: ${estimatedTokens}`);
        }

        if (this.config.maxCost && (usage.cost + estimatedCost > this.config.maxCost)) {
            throw new BudgetExceededError(`Cost budget exceeded for user ${userId}. Limit: $${this.config.maxCost}, Current: $${usage.cost}, Attempted: $${estimatedCost.toFixed(4)}`);
        }

        // Update Usage
        usage.tokens += estimatedTokens;
        usage.cost += estimatedCost;
        this.cache.set(userId, usage);
    }
}
