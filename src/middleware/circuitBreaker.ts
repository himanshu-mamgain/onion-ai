import { LRUCache } from 'lru-cache';

export interface BudgetConfig {
    maxTokens: number;
    maxCost?: number; // Optional dollar limit (e.g. 0.02)
    windowMs?: number; // Default 60000 (1 min)
    costPer1kTokens?: number; // Default 0.002
}

export interface UserUsage {
    tokens: number;
    cost: number;
    lastReset: number;
}

export interface BudgetStore {
    get(userId: string): Promise<UserUsage | undefined> | UserUsage | undefined;
    set(userId: string, usage: UserUsage): Promise<void> | void;
}

class MemoryBudgetStore implements BudgetStore {
    private cache: LRUCache<string, UserUsage>;

    constructor(ttl: number) {
        this.cache = new LRUCache<string, UserUsage>({
            max: 1000,
            ttl: ttl,
            ttlAutopurge: true
        });
    }

    get(userId: string): UserUsage | undefined {
        return this.cache.get(userId);
    }

    set(userId: string, usage: UserUsage): void {
        this.cache.set(userId, usage);
    }
}

export class BudgetExceededError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'BudgetExceededError';
    }
}

export class CircuitBreaker {
    private store: BudgetStore;
    private config: BudgetConfig;
    private windowMs: number;
    private costPer1kTokens: number;

    constructor(config: BudgetConfig, store?: BudgetStore) {
        this.config = config;
        this.windowMs = config.windowMs || 60000;
        this.costPer1kTokens = config.costPer1kTokens || 0.002;

        this.store = store || new MemoryBudgetStore(this.windowMs);
    }

    async checkLimit(userId: string, estimatedTokens: number): Promise<void> {
        let usage = await this.store.get(userId);
        const now = Date.now();

        if (!usage) {
            usage = { tokens: 0, cost: 0, lastReset: now };
        }

        // Sliding window / Reset check
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

        await this.store.set(userId, usage);
    }
}
