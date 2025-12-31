import { Sentry } from '../src/layers/sentry';

describe('Sentry Layer (Rate Limiting)', () => {
    let sentry: Sentry;

    beforeEach(() => {
        sentry = new Sentry({
            maxTokensPerPrompt: 10,
            maxTokensPerResponse: 100,
            maxTokensPerMinute: 1000,
            maxRequestsPerMinute: 2, // Low limit for testing
            preventRecursivePrompts: true
        });
    });

    test('should enforce rate checking', () => {
        // 1st request
        expect(sentry.checkRateLimit().safe).toBe(true);
        // 2nd request
        expect(sentry.checkRateLimit().safe).toBe(true);
        // 3rd request (should fail)
        const result = sentry.checkRateLimit();
        expect(result.safe).toBe(false);
        expect(result.threats).toContain('Rate limit exceeded (Max requests per minute)');
    });

    test('should check token limits', () => {
        const longPrompt = 'This is a prompt that is definitely going to exceed the very small token limit set in the configuration.';
        const result = sentry.checkTokenCount(longPrompt);
        expect(result.safe).toBe(false);
        expect(result.threats.some(t => t.includes('Prompt exceeds max token limit'))).toBe(true);
    });

    test('should allow short prompts within limits', () => {
        const shortPrompt = 'Hi';
        const result = sentry.checkTokenCount(shortPrompt);
        expect(result.safe).toBe(true);
    });
});
